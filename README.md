# SecureShop — CET431 Software Security Project (Phase 1)

A small e-commerce site built as **one codebase with two modes**:

| Mode | How to run | What it is |
|---|---|---|
| **naive**  | `SECURE_MODE=0` | Contains the vulnerabilities from Labs 1–5, on purpose |
| **secure** | `SECURE_MODE=1` (default) | Same features, with the defenses turned on |

Every vulnerable / defended spot in `app.py` is tagged `[T1]`..`[T7]` so you
can `grep` for it. See `docs/coverage-matrix.md` for the full write-up.

## Requirements
- Python 3.10+
- `pip install -r requirements.txt` (Flask; `requests` is only needed to run
  the attack script)

## Setup & run

```bash
cd secureshop
pip install -r requirements.txt

# NAIVE build (vulnerable) — for the attack demo
SECURE_MODE=0 python3 app.py            # http://127.0.0.1:5000

# SECURE build (defended) — the real deliverable
SECURE_MODE=1 python3 app.py            # http://127.0.0.1:5000
```

The database (`secureshop.db`, SQLite) is created and seeded automatically
the first time the app runs. Delete the file to start fresh.

### Test accounts (seeded automatically)
| Username | Password | Role |
|---|---|---|
| `alice` | `Alice#2026pass` | user |
| `admin` | `Admin#2026pass` | admin |

Both accounts start with **$100.00 store credit** and are pre-confirmed.

### Simulated email server
There is no real mail server in this course environment. Every email
SecureShop "sends" (confirmation links, verification codes, newsletter
coupons) is instead stored in the database and shown at **`/dev/mailbox`**.
This stands in for reading the email in a real inbox / Burp's email client.

### Environment variables
| Variable | Default | Meaning |
|---|---|---|
| `SECURE_MODE` | `1` | `1` = secure build, `0` = naive/vulnerable build |
| `PORT` | `5000` | Port to listen on |
| `SECRET_KEY` | `dev-only-change-me` | Flask session signing key |
| `COOKIE_SECURE` | `0` | Set `1` behind HTTPS to mark the session cookie `Secure` |
| `POLICY_ENFORCE` | `0` | `1` = enforce the admin location/time policy (Lab 5, [T7]) |
| `ADMIN_HOME_LAT`/`ADMIN_HOME_LON`/`ADMIN_RADIUS_KM` | Cairo, 50 | admin "home" point + allowed radius |
| `TZ_NAME` | `Africa/Cairo` | timezone used for the admin login time window |
| `DEV_MAILBOX` | `1` | expose `/dev/mailbox` (course environment only — **never ship this to production**) |

`POLICY_ENFORCE` defaults to off so the demo/test accounts can log in from
any machine; turn it on to show the Lab 5 location/time policy working.

## Running the attack evidence script

`attacks/run_all.py` runs the 6 attacks from Labs 1, 2 and 3 against a
running server and prints PASS/FAIL for each. Run it twice: once against the
naive build (everything should say **ATTACK SUCCEEDED**) and once against
the secure build (everything should say **attack failed (defended)**).

```bash
# terminal 1
SECURE_MODE=0 PORT=5001 python3 app.py
# terminal 2
python3 attacks/run_all.py http://127.0.0.1:5001 naive

# terminal 1 (restart)
rm secureshop.db
SECURE_MODE=1 PORT=5002 python3 app.py
# terminal 2
python3 attacks/run_all.py http://127.0.0.1:5002 secure
```

## Architecture (one page)

```
Browser  ──HTTP──>  Flask app (app.py)  ──SQL──>  SQLite (secureshop.db)
                         │
                         ├─ templates/   Jinja2 pages (server-rendered)
                         ├─ static/      CSS only (light/dark aware)
                         └─ attacks/     attack evidence script (Labs 1-3)
```

- **Single process, server-rendered** Flask app. No client-side framework;
  every price/total/role/order-state decision is made in `app.py`, never
  trusted from the browser.
- **Session** = signed Flask cookie (`SECRET_KEY`), `HttpOnly` + `SameSite=Lax`.
  Holds `uid` (logged in) or `pending_uid` (mid second-factor), never a
  plain username that the browser could edit.
- **SQLite** is the single source of truth for prices, roles, coupon usage,
  order state and store credit. The cart only ever stores `{product_id:
  qty}` in the session — never a price.
- **Orders are a small state machine**: `pending → paid` (or `failed`).
  Only a `paid` order can ever be shown as a confirmation (`[T4]`).
- **Feature → file map**: registration/login/2FA/anomaly check in the
  `login`/`login2`/`register` views; catalogue in `index`/`product`; cart in
  `cart_*`; checkout/orders in `checkout`/`order_*`; admin panel in
  `admin_*`; account page in `account`.

See `docs/threat-model.md` and `docs/coverage-matrix.md` for the security
write-up, and `docs/architecture.md` for more detail than the overview above.
