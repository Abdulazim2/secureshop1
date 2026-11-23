"""
SecureShop - CET431 Software Security project (Phase 1)

One code base, two modes:
  SECURE_MODE=0  -> "naive" build: contains the vulnerabilities taught in Labs 1-5
  SECURE_MODE=1  -> "secure" build: same features, defenses turned on (default)

Every vulnerable spot is tagged [T1]..[T7] so you can search for it:
  [T1] client-side price trust        [T5] 2FA broken logic
  [T2] coupon rule enforcement        [T6] behavioural (typing rhythm) anomaly
  [T3] exceptional input (email)      [T7] location / time policy
  [T4] workflow validation (order)
"""
import json
import math
import os
import re
import secrets
import sqlite3
import statistics
import hmac
from datetime import datetime
from decimal import Decimal, InvalidOperation
from functools import wraps

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------
# Configuration (all from environment variables, see README)
# --------------------------------------------------------------------------
SECURE = os.environ.get("SECURE_MODE", "1") == "1"
DB_PATH = os.environ.get("DB_PATH", "secureshop.db")
DEV_MAILBOX = os.environ.get("DEV_MAILBOX", "1") == "1"   # simulated email server

# [T7] policy for admin logins (enforced only in secure mode)
POLICY_ENFORCE = os.environ.get("POLICY_ENFORCE", "0") == "1"
HOME_LAT = float(os.environ.get("ADMIN_HOME_LAT", "30.0444"))
HOME_LON = float(os.environ.get("ADMIN_HOME_LON", "31.2357"))
RADIUS_KM = float(os.environ.get("ADMIN_RADIUS_KM", "50"))
WINDOW_START, WINDOW_END = 8, 22            # allowed hours: 8 <= hour < 22
TIMEZONE = os.environ.get("TZ_NAME", "Africa/Cairo")

# [T6] anomaly detection
Z_THRESHOLD = 3.0
MIN_SAMPLES = 3            # typing samples needed before a profile is trusted
FEATURES = ["speed", "avg_gap"]

# [T3] limits
EMAIL_DB_LIMIT = 255       # naive build silently cuts emails at this length
EMAIL_MAX = 254            # secure build rejects anything longer (RFC 5321)

# [T2] limits
MAX_DISCOUNT_PCT = 50

# [T5] one-time code settings (secure build)
OTP_TTL_SECONDS = 300
OTP_MAX_ATTEMPTS = 5

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  credit INTEGER NOT NULL DEFAULT 10000,
  confirmed INTEGER NOT NULL DEFAULT 0,
  confirm_token TEXT,
  display_name TEXT DEFAULT '',
  address TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
  description TEXT NOT NULL, price INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS coupons(
  code TEXT PRIMARY KEY, percent INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS coupon_uses(
  user_id INTEGER NOT NULL, code TEXT NOT NULL, PRIMARY KEY(user_id, code));
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT, public_id TEXT UNIQUE NOT NULL,
  user_id INTEGER NOT NULL, subtotal INTEGER NOT NULL, discount INTEGER NOT NULL,
  total INTEGER NOT NULL, coupons TEXT DEFAULT '', status TEXT NOT NULL,
  created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS order_items(
  order_id INTEGER NOT NULL, product_id INTEGER NOT NULL, name TEXT NOT NULL,
  price INTEGER NOT NULL, qty INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS otp(
  user_id INTEGER PRIMARY KEY, code TEXT NOT NULL, expires REAL NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS mailbox(
  id INTEGER PRIMARY KEY AUTOINCREMENT, to_addr TEXT NOT NULL,
  subject TEXT NOT NULL, body TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS typing(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
  speed REAL NOT NULL, avg_gap REAL NOT NULL);
CREATE TABLE IF NOT EXISTS newsletter(email TEXT PRIMARY KEY);
"""


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and seed demo data (only when the DB file is new)."""
    fresh = not os.path.exists(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    if fresh:
        users = [  # username, email, password, role
            ("alice", "alice@example.com", "Alice#2026pass", "user"),
            ("admin", "admin@secureshop.com", "Admin#2026pass", "admin"),
        ]
        for u, e, p, r in users:
            db.execute("INSERT INTO users(username,email,password_hash,role,confirmed)"
                       " VALUES(?,?,?,?,1)", (u, e, generate_password_hash(p), r))
        products = [
            ("Ceramic Mug", "A sturdy 350ml mug.", 500),
            ("Notebook", "A5 dotted notebook, 120 pages.", 1250),
            ("Cotton T-Shirt", "Plain black tee, sizes S-XL.", 2000),
            ("Wireless Headphones", "Bluetooth, 20h battery.", 5999),
            ("Running Sneakers", "Lightweight everyday trainers.", 8900),
            ("Premium Leather Jacket", "Hand-stitched, limited edition.", 133700),
        ]
        db.executemany("INSERT INTO products(name,description,price) VALUES(?,?,?)", products)
        db.executemany("INSERT INTO coupons(code,percent) VALUES(?,?)",
                       [("NEWCUST5", 5), ("SIGNUP30", 30)])
    db.commit()
    db.close()


def send_mail(to_addr, subject, body):
    """Simulated email server: messages are stored in the DB (see /dev/mailbox)."""
    get_db().execute("INSERT INTO mailbox(to_addr,subject,body,created) VALUES(?,?,?,?)",
                     (to_addr, subject, body, datetime.now().isoformat(timespec="seconds")))
    get_db().commit()


def money(cents):
    return f"${cents / 100:,.2f}"


app.jinja_env.filters["money"] = money


def to_cents(text):
    """'12.50' -> 1250. Raises ValueError for bad / negative / huge values."""
    try:
        value = Decimal(text.strip())
    except (InvalidOperation, AttributeError):
        raise ValueError("Price must be a number.")
    if value <= 0 or value > Decimal("100000") or value.as_tuple().exponent < -2:
        raise ValueError("Price must be between 0.01 and 100000.00 (2 decimals).")
    return int(value * 100)


# --------------------------------------------------------------------------
# Current user + decorators
# --------------------------------------------------------------------------
@app.before_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid:
        g.user = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if g.user is None:
            session.clear()


@app.context_processor
def inject_globals():
    cart = session.get("cart", {})
    return {"secure": SECURE, "user": g.get("user"), "dev_mailbox": DEV_MAILBOX,
            "cart_count": sum(i["qty"] for i in cart.values())}


def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if g.user is None:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if g.user is None:
            return redirect(url_for("login"))
        if g.user["role"] != "admin":
            abort(403)
        return view(*a, **kw)
    return wrapper


# --------------------------------------------------------------------------
# Catalogue
# --------------------------------------------------------------------------
@app.route("/")
def index():
    q = request.args.get("q", "").strip()[:100]
    db = get_db()
    if q:
        rows = db.execute("SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
                          (f"%{q}%", f"%{q}%")).fetchall()
    else:
        rows = db.execute("SELECT * FROM products").fetchall()
    return render_template("index.html", products=rows, q=q)


@app.route("/product/<int:pid>")
def product(pid):
    p = get_db().execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if p is None:
        abort(404)
    return render_template("product.html", p=p)


# --------------------------------------------------------------------------
# Cart  [T1] [T2]
# --------------------------------------------------------------------------
def cart_lines():
    """Return the cart as a list of lines with prices.

    [T1] NAIVE: the price stored in the cart came from the browser (hidden form
         field), so the customer decides what to pay.
    [T1] SECURE: the cart only keeps product id + quantity; the price is always
         read from the database here.
    """
    db = get_db()
    lines = []
    for pid, item in session.get("cart", {}).items():
        p = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if p is None:
            continue
        price = p["price"] if SECURE else item.get("price", p["price"])
        lines.append({"id": p["id"], "name": p["name"], "price": price,
                      "qty": item["qty"], "subtotal": price * item["qty"]})
    return lines


def cart_totals(lines=None):
    """subtotal, discount and total, always recomputed from scratch."""
    lines = cart_lines() if lines is None else lines
    db = get_db()
    subtotal = sum(l["subtotal"] for l in lines)
    pct = 0
    for code in session.get("coupons", []):
        c = db.execute("SELECT * FROM coupons WHERE code=? AND active=1", (code,)).fetchone()
        if c:
            pct += c["percent"]
    if SECURE:
        pct = min(pct, MAX_DISCOUNT_PCT)          # [T2] cap on total discount
    discount = subtotal * pct // 100
    return {"subtotal": subtotal, "discount": discount, "pct": pct,
            "total": max(0, subtotal - discount)}


@app.route("/cart")
def cart():
    lines = cart_lines()
    return render_template("cart.html", lines=lines, t=cart_totals(lines),
                           coupons=session.get("coupons", []))


@app.route("/cart/add", methods=["POST"])
def cart_add():
    try:
        pid = int(request.form.get("productId", ""))
        qty = int(request.form.get("quantity", "1"))
    except ValueError:
        abort(400)
    p = get_db().execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if p is None:
        abort(404)
    if SECURE and not 1 <= qty <= 10:             # [T1] validate quantity
        flash("Quantity must be between 1 and 10.", "error")
        return redirect(url_for("product", pid=pid))
    cart_data = session.get("cart", {})
    item = cart_data.get(str(pid), {"qty": 0})
    item["qty"] += qty
    if SECURE:
        item["qty"] = min(item["qty"], 10)
    else:                                         # [T1] NAIVE: trusts the price sent by the browser
        try:
            item["price"] = int(request.form.get("price", p["price"]))
        except ValueError:
            item["price"] = p["price"]
    cart_data[str(pid)] = item
    session["cart"] = cart_data
    flash(f"Added {p['name']} to your cart.", "ok")
    return redirect(url_for("cart"))


@app.route("/cart/update", methods=["POST"])
def cart_update():
    cart_data = session.get("cart", {})
    pid = request.form.get("productId", "")
    if pid in cart_data:
        try:
            qty = int(request.form.get("quantity", "1"))
        except ValueError:
            abort(400)
        if qty <= 0:
            del cart_data[pid]
        elif SECURE and qty > 10:
            flash("Maximum quantity is 10.", "error")
        else:
            cart_data[pid]["qty"] = qty
    session["cart"] = cart_data
    return redirect(url_for("cart"))


@app.route("/cart/remove", methods=["POST"])
def cart_remove():
    cart_data = session.get("cart", {})
    cart_data.pop(request.form.get("productId", ""), None)
    session["cart"] = cart_data
    return redirect(url_for("cart"))


@app.route("/cart/coupon", methods=["POST"])
def cart_coupon():
    code = request.form.get("code", "").strip().upper()
    applied = session.get("coupons", [])
    db = get_db()
    if not re.fullmatch(r"[A-Z0-9]{3,20}", code):
        flash("Invalid coupon format.", "error")
        return redirect(url_for("cart"))
    c = db.execute("SELECT * FROM coupons WHERE code=? AND active=1", (code,)).fetchone()
    if c is None:
        flash("Coupon not found or expired.", "error")
        return redirect(url_for("cart"))

    if SECURE:
        # [T2] SECURE: the full set of applied coupons is checked, and a coupon
        # that this account already used on a paid order is rejected too.
        if code in applied:
            flash("This coupon is already applied.", "error")
        elif g.user and db.execute("SELECT 1 FROM coupon_uses WHERE user_id=? AND code=?",
                                   (g.user["id"], code)).fetchone():
            flash("You already used this coupon.", "error")
        else:
            applied.append(code)
            flash("Coupon applied.", "ok")
    else:
        # [T2] NAIVE: only compares with the LAST coupon, so A,B,A,B,... stacks forever.
        if code == session.get("last_coupon"):
            flash("Coupon already applied.", "error")
        else:
            applied.append(code)
            session["last_coupon"] = code
            flash("Coupon applied.", "ok")
    session["coupons"] = applied
    return redirect(url_for("cart"))


@app.route("/cart/coupons/clear", methods=["POST"])
def cart_coupons_clear():
    session["coupons"] = []
    session.pop("last_coupon", None)
    return redirect(url_for("cart"))


# --------------------------------------------------------------------------
# Newsletter -> issues a coupon
# --------------------------------------------------------------------------
@app.route("/newsletter", methods=["POST"])
def newsletter():
    email = request.form.get("email", "").strip()
    if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{3,190}", email):
        flash("Please enter a valid email address.", "error")
        return redirect(request.referrer or url_for("index"))
    db = get_db()
    if db.execute("SELECT 1 FROM newsletter WHERE email=?", (email.lower(),)).fetchone():
        flash("This email is already subscribed.", "error")
    else:
        db.execute("INSERT INTO newsletter(email) VALUES(?)", (email.lower(),))
        db.commit()
        send_mail(email, "Welcome to SecureShop", "Thanks for subscribing! Your coupon: SIGNUP30")
        flash("Subscribed! Your coupon code is SIGNUP30 (also sent to your email).", "ok")
    return redirect(request.referrer or url_for("index"))


# --------------------------------------------------------------------------
# Checkout and orders  [T4]
# --------------------------------------------------------------------------
def create_order(user_id, lines, totals, status):
    db = get_db()
    public_id = secrets.token_urlsafe(12)         # unguessable id
    cur = db.execute(
        "INSERT INTO orders(public_id,user_id,subtotal,discount,total,coupons,status,created)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (public_id, user_id, totals["subtotal"], totals["discount"], totals["total"],
         ",".join(session.get("coupons", [])), status,
         datetime.now().isoformat(timespec="seconds")))
    oid = cur.lastrowid
    for l in lines:
        db.execute("INSERT INTO order_items(order_id,product_id,name,price,qty) VALUES(?,?,?,?,?)",
                   (oid, l["id"], l["name"], l["price"], l["qty"]))
    db.commit()
    return oid, public_id


def clear_cart():
    session.pop("cart", None)
    session.pop("coupons", None)
    session.pop("last_coupon", None)


@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    db = get_db()
    lines = cart_lines()
    if not lines:
        flash("Your cart is empty.", "error")
        return redirect(url_for("cart"))
    t = cart_totals(lines)

    if not SECURE:
        # [T4] NAIVE: checkout only takes the money. The ORDER itself is created later
        # by /order-confirmation, which assumes you only get there after paying.
        if g.user["credit"] < t["total"]:
            flash("Not enough store credit for this order.", "error")
            return redirect(url_for("cart"))
        db.execute("UPDATE users SET credit=credit-? WHERE id=?", (t["total"], g.user["id"]))
        db.commit()
        return redirect("/order-confirmation?order-confirmation=true")

    # [T4] SECURE: an order is a small state machine: pending -> paid.
    # The total is recomputed here, payment is one atomic conditional UPDATE
    # (so two parallel requests cannot spend the same credit twice), and only a
    # 'paid' order can ever be shown as confirmed.
    oid, public_id = create_order(g.user["id"], lines, t, "pending")
    cur = db.execute("UPDATE users SET credit=credit-? WHERE id=? AND credit>=?",
                     (t["total"], g.user["id"], t["total"]))
    if cur.rowcount != 1:
        db.execute("UPDATE orders SET status='failed' WHERE id=?", (oid,))
        db.commit()
        flash("Not enough store credit for this order.", "error")
        return redirect(url_for("cart"))
    db.execute("UPDATE orders SET status='paid' WHERE id=?", (oid,))
    for code in session.get("coupons", []):
        db.execute("INSERT OR IGNORE INTO coupon_uses(user_id,code) VALUES(?,?)",
                   (g.user["id"], code))
    db.commit()
    clear_cart()
    return redirect(url_for("order_detail", public_id=public_id))


if not SECURE:
    @app.route("/order-confirmation")
    @login_required
    def order_confirmation_naive():
        # [T4] NAIVE: "?order-confirmation=true" is enough. It builds an order from
        # whatever is in the cart right now and never checks that it was paid.
        if request.args.get("order-confirmation") != "true":
            abort(404)
        lines = cart_lines()
        if not lines:
            return redirect(url_for("orders"))
        _oid, public_id = create_order(g.user["id"], lines, cart_totals(lines), "paid")
        clear_cart()
        return redirect(url_for("order_detail", public_id=public_id))


@app.route("/orders")
@login_required
def orders():
    rows = get_db().execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC",
                            (g.user["id"],)).fetchall()
    return render_template("orders.html", orders=rows)


@app.route("/orders/<public_id>")
@login_required
def order_detail(public_id):
    db = get_db()
    o = db.execute("SELECT * FROM orders WHERE public_id=? AND user_id=?",
                   (public_id, g.user["id"])).fetchone()      # ownership check
    if o is None:
        abort(404)
    if SECURE and o["status"] != "paid":                       # [T4] only paid orders confirm
        abort(404)
    items = db.execute("SELECT * FROM order_items WHERE order_id=?", (o["id"],)).fetchall()
    return render_template("order.html", o=o, items=items)


# --------------------------------------------------------------------------
# Registration + email confirmation  [T3]
# --------------------------------------------------------------------------
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,189}\.[A-Za-z]{2,}")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    db = get_db()

    if SECURE:
        # [T3] SECURE: ONE strict validation, applied to the exact value that is
        # stored and used. Too long -> rejected (never silently cut).
        errors = []
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            errors.append("Username: 3-30 letters, digits or underscore.")
        if len(email) > EMAIL_MAX or not EMAIL_RE.fullmatch(email):
            errors.append(f"Enter a valid email address (max {EMAIL_MAX} characters).")
        if not 8 <= len(password) <= 128:
            errors.append("Password must be 8-128 characters.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html"), 400
        if db.execute("SELECT 1 FROM users WHERE username=? OR lower(email)=lower(?)",
                      (username, email)).fetchone():
            flash("Username or email is already registered.", "error")
            return render_template("register.html"), 400
        stored_email, role = email, "user"        # role is NEVER derived from the email
    else:
        # [T3] NAIVE: the email is cut to 255 characters when stored, but the
        # confirmation mail goes to the FULL address. The role is then decided
        # from the stored (cut) domain: @secureshop.com => staff => admin.
        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html"), 400
        if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            flash("Username is already registered.", "error")
            return render_template("register.html"), 400
        stored_email = email[:EMAIL_DB_LIMIT]
        role = "admin" if stored_email.lower().endswith("@secureshop.com") else "user"

    token = secrets.token_urlsafe(24)
    db.execute("INSERT INTO users(username,email,password_hash,role,confirmed,confirm_token)"
               " VALUES(?,?,?,?,0,?)",
               (username, stored_email, generate_password_hash(password), role, token))
    db.commit()
    send_mail(email, "Confirm your SecureShop account",
              f"Welcome {username}! Confirm your account: /confirm/{token}")
    flash("Account created. Check your email to confirm it.", "ok")
    return redirect(url_for("login"))


@app.route("/confirm/<token>")
def confirm(token):
    db = get_db()
    u = db.execute("SELECT id FROM users WHERE confirm_token=? AND confirmed=0",
                   (token,)).fetchone()
    if u is None:
        flash("Invalid or already used confirmation link.", "error")
        return redirect(url_for("login"))
    db.execute("UPDATE users SET confirmed=1, confirm_token=NULL WHERE id=?", (u["id"],))
    db.commit()
    flash("Account confirmed. You can log in now.", "ok")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# [T6] behavioural anomaly detection (Lab 4: z-score)
# --------------------------------------------------------------------------
def parse_rhythm(raw):
    """Browser JS sends the gaps (ms) between password keystrokes as JSON."""
    try:
        gaps = json.loads(raw or "[]")
    except ValueError:
        return None
    if (not isinstance(gaps, list) or not 2 <= len(gaps) <= 64
            or any(not isinstance(x, (int, float)) or not 0 < x < 10000 for x in gaps)):
        return None
    total = sum(gaps) / 1000
    return {"speed": (len(gaps) + 1) / total, "avg_gap": statistics.mean(gaps) / 1000}


def z_score(value, mean, std):
    # Lab 4 guards std==0. We use a small floor relative to the mean so that a
    # profile built from few samples is not absurdly strict.
    std = max(std, 0.05 * abs(mean), 1e-6)
    return abs(value - mean) / std


def rhythm_check(user_id, feats):
    """Return (is_anomaly, score). Not enrolled yet -> (False, 0)."""
    rows = get_db().execute("SELECT speed, avg_gap FROM typing WHERE user_id=?"
                            " ORDER BY id DESC LIMIT 20", (user_id,)).fetchall()
    if len(rows) < MIN_SAMPLES:
        return False, 0.0
    if feats is None:               # enrolled user but no human typing data (script/paste)
        return True, float("inf")
    scores = []
    for f in FEATURES:
        values = [r[f] for r in rows]
        scores.append(z_score(feats[f], statistics.mean(values), statistics.pstdev(values)))
    score = sum(scores) / len(scores)
    return score > Z_THRESHOLD, score


# --------------------------------------------------------------------------
# [T7] location + time policy (Lab 5)
# --------------------------------------------------------------------------
def haversine_km(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dlat, dlon = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlon / 2) ** 2
    return 6371 * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def policy_violation():
    """Return a reason string if this admin login breaks the policy, else None."""
    try:
        lat, lon = float(request.form.get("lat", "")), float(request.form.get("lon", ""))
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            raise ValueError
    except ValueError:
        return "location missing"
    if haversine_km(HOME_LAT, HOME_LON, lat, lon) > RADIUS_KM:
        return "location"
    now = datetime.now(ZoneInfo(TIMEZONE)) if ZoneInfo else datetime.utcnow()
    if not WINDOW_START <= now.hour < WINDOW_END:
        return "time"
    return None


# --------------------------------------------------------------------------
# Login, second step, logout  [T5]
# --------------------------------------------------------------------------
def complete_login(user_id):
    session.clear()                  # new session after login (prevents fixation)
    session["uid"] = user_id


def issue_otp(user_id, email, digits):
    code = "".join(secrets.choice("0123456789") for _ in range(digits))
    db = get_db()
    db.execute("INSERT OR REPLACE INTO otp(user_id,code,expires,attempts) VALUES(?,?,?,0)",
               (user_id, code, datetime.now().timestamp() + OTP_TTL_SECONDS))
    db.commit()
    send_mail(email, "Your SecureShop verification code", f"Your verification code is: {code}")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    # same message for unknown user and wrong password (no user enumeration)
    if user is None or not check_password_hash(user["password_hash"], password):
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401
    if not user["confirmed"]:
        flash("Please confirm your email first.", "error")
        return render_template("login.html"), 403

    if not SECURE:
        # [T5] NAIVE: admins get a second step, but WHO is being verified is kept
        # in a plain cookie (verify=<username>) that the browser can edit.
        if user["role"] == "admin":
            resp = redirect(url_for("login2"))
            resp.set_cookie("verify", user["username"])
            return resp
        complete_login(user["id"])
        return redirect(url_for("index"))

    reasons = []
    # [T7] admins: location/time policy, then always a second factor
    if user["role"] == "admin":
        if POLICY_ENFORCE:
            why = policy_violation()
            if why:
                app.logger.warning("admin login blocked by policy (%s)", why)
                flash("Login blocked by security policy.", "error")
                return render_template("login.html"), 403
        reasons.append("admin")
    # [T6] behavioural check for everyone
    feats = parse_rhythm(request.form.get("rhythm"))
    anomaly, score = rhythm_check(user["id"], feats)
    if anomaly:
        app.logger.warning("typing anomaly for %s (score %.1f)", user["username"], score)
        reasons.append("anomaly")

    if reasons:
        # [T5] SECURE: the identity waiting for the second step lives in the
        # server-side session, signed by the server, not in a plain cookie.
        session.clear()
        session["pending_uid"] = user["id"]
        issue_otp(user["id"], user["email"], digits=6)
        return redirect(url_for("login2"))

    if feats:
        db.execute("INSERT INTO typing(user_id,speed,avg_gap) VALUES(?,?,?)",
                   (user["id"], feats["speed"], feats["avg_gap"]))
        db.commit()
    complete_login(user["id"])
    return redirect(url_for("index"))


@app.route("/login2", methods=["GET", "POST"])
def login2():
    db = get_db()
    if not SECURE:
        # [T5] NAIVE: trusts the cookie, makes a 4-digit code for whoever the cookie
        # names, and allows unlimited guesses.
        name = request.cookies.get("verify", "")
        user = db.execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()
        if user is None:
            return redirect(url_for("login"))
        if request.method == "GET":
            issue_otp(user["id"], user["email"], digits=4)
            return render_template("login2.html")
        row = db.execute("SELECT code FROM otp WHERE user_id=?", (user["id"],)).fetchone()
        if row and request.form.get("mfa-code", "") == row["code"]:
            complete_login(user["id"])
            return redirect(url_for("index"))
        flash("Incorrect verification code.", "error")
        return render_template("login2.html")

    uid = session.get("pending_uid")
    if uid is None:
        return redirect(url_for("login"))
    if request.method == "GET":
        return render_template("login2.html")
    row = db.execute("SELECT * FROM otp WHERE user_id=?", (uid,)).fetchone()
    if row is None or row["expires"] < datetime.now().timestamp() or row["attempts"] >= OTP_MAX_ATTEMPTS:
        db.execute("DELETE FROM otp WHERE user_id=?", (uid,))
        db.commit()
        session.clear()
        flash("Verification expired or locked. Please log in again.", "error")
        return redirect(url_for("login"))
    db.execute("UPDATE otp SET attempts=attempts+1 WHERE user_id=?", (uid,))
    db.commit()
    if hmac.compare_digest(row["code"], request.form.get("mfa-code", "").strip()):
        db.execute("DELETE FROM otp WHERE user_id=?", (uid,))     # single use
        db.commit()
        complete_login(uid)
        return redirect(url_for("index"))
    flash("Incorrect verification code.", "error")
    return render_template("login2.html"), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    resp = redirect(url_for("index"))
    resp.delete_cookie("verify")
    return resp


# --------------------------------------------------------------------------
# Account page
# --------------------------------------------------------------------------
@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("display_name", "").strip()
        address = request.form.get("address", "").strip()
        if len(name) > 60 or len(address) > 200:
            flash("Name max 60 characters, address max 200.", "error")
        else:
            db.execute("UPDATE users SET display_name=?, address=? WHERE id=?",
                       (name, address, g.user["id"]))
            db.commit()
            flash("Profile updated.", "ok")
        return redirect(url_for("account"))
    rows = db.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC",
                      (g.user["id"],)).fetchall()
    return render_template("account.html", orders=rows)


# --------------------------------------------------------------------------
# Admin panel
# --------------------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    return render_template("admin.html",
                           users=db.execute("SELECT * FROM users ORDER BY id").fetchall(),
                           products=db.execute("SELECT * FROM products ORDER BY id").fetchall(),
                           coupons=db.execute("SELECT * FROM coupons").fetchall())


@app.route("/admin/users/<int:uid>/role", methods=["POST"])
@admin_required
def admin_user_role(uid):
    role = request.form.get("role")
    if role not in ("user", "admin") or uid == g.user["id"]:
        abort(400)
    get_db().execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    get_db().commit()
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_user_delete(uid):
    if uid == g.user["id"]:
        abort(400)
    get_db().execute("DELETE FROM users WHERE id=?", (uid,))
    get_db().commit()
    return redirect(url_for("admin"))


@app.route("/admin/products", methods=["POST"])
@admin_required
def admin_product_add():
    name = request.form.get("name", "").strip()
    desc = request.form.get("description", "").strip()
    try:
        price = to_cents(request.form.get("price", ""))
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("admin"))
    if not 1 <= len(name) <= 80 or len(desc) > 500:
        flash("Name 1-80 characters, description max 500.", "error")
        return redirect(url_for("admin"))
    get_db().execute("INSERT INTO products(name,description,price) VALUES(?,?,?)",
                     (name, desc, price))
    get_db().commit()
    flash("Product added.", "ok")
    return redirect(url_for("admin"))


@app.route("/admin/products/<int:pid>/price", methods=["POST"])
@admin_required
def admin_product_price(pid):
    try:
        price = to_cents(request.form.get("price", ""))
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("admin"))
    get_db().execute("UPDATE products SET price=? WHERE id=?", (price, pid))
    get_db().commit()
    return redirect(url_for("admin"))


@app.route("/admin/products/<int:pid>/delete", methods=["POST"])
@admin_required
def admin_product_delete(pid):
    get_db().execute("DELETE FROM products WHERE id=?", (pid,))
    get_db().commit()
    return redirect(url_for("admin"))


@app.route("/admin/coupons", methods=["POST"])
@admin_required
def admin_coupon_add():
    code = request.form.get("code", "").strip().upper()
    try:
        pct = int(request.form.get("percent", ""))
    except ValueError:
        pct = 0
    if not re.fullmatch(r"[A-Z0-9]{3,20}", code) or not 1 <= pct <= MAX_DISCOUNT_PCT:
        flash(f"Code: 3-20 letters/digits. Percent: 1-{MAX_DISCOUNT_PCT}.", "error")
    else:
        get_db().execute("INSERT OR REPLACE INTO coupons(code,percent,active) VALUES(?,?,1)",
                         (code, pct))
        get_db().commit()
    return redirect(url_for("admin"))


@app.route("/admin/coupons/<code>/toggle", methods=["POST"])
@admin_required
def admin_coupon_toggle(code):
    get_db().execute("UPDATE coupons SET active=1-active WHERE code=?", (code,))
    get_db().commit()
    return redirect(url_for("admin"))


# --------------------------------------------------------------------------
# Simulated email server (course environment only)
# --------------------------------------------------------------------------
if DEV_MAILBOX:
    @app.route("/dev/mailbox")
    def dev_mailbox():
        rows = get_db().execute("SELECT * FROM mailbox ORDER BY id DESC LIMIT 100").fetchall()
        return render_template("mailbox.html", mails=rows)


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, msg="You are not allowed to do that."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, msg="Page not found."), 404


@app.errorhandler(400)
def bad_request(_e):
    return render_template("error.html", code=400, msg="Bad request."), 400


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
