import requests
s = requests.Session()
for i in range(5):
    r = s.post("http://127.0.0.1:5000/login",
               data={"username": "alice", "password": "Alice#2026pass"})
    print(i, r.status_code, r.url)
    s.post("http://127.0.0.1:5000/logout")