local = "a" * (255 - len("@secureshop.com"))
email = local + "@secureshop.com" + ".evil.example"
print("Email to use:", email)
print("Length:", len(email))