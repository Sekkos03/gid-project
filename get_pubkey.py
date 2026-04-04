import requests, json, sys

KEYCLOAK_URL = "http://localhost:8080"
REALM = "gid-realm"

print("Step 1: Connecting to Keycloak...")

try:
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
    print(f"Fetching: {url}")
    r = requests.get(url, timeout=5)
    print(f"Status code: {r.status_code}")
    print(f"Response: {r.text[:200]}")
except requests.exceptions.ConnectionError:
    print("ERROR: Cannot connect to Keycloak!")
    print("Make sure Keycloak is running at http://localhost:8080")
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)

print("\nStep 2: Parsing keys...")
jwks = r.json()
print(f"Found {len(jwks.get('keys', []))} key(s)")

print("\nStep 3: Extracting public key...")
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    import base64

    key_data = jwks['keys'][0]
    print(f"Key algorithm: {key_data.get('alg')}")
    print(f"Key type: {key_data.get('kty')}")

    def b64_to_int(b64):
        data = base64.urlsafe_b64decode(b64 + '==')
        return int.from_bytes(data, 'big')

    pub_numbers = RSAPublicNumbers(
        e=b64_to_int(key_data['e']),
        n=b64_to_int(key_data['n'])
    )
    public_key = pub_numbers.public_key(default_backend())
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("keycloak_pub.pem", "wb") as f:
        f.write(pem)

    print("\nSUCCESS! Public key saved to keycloak_pub.pem")
    print("\nKey preview:")
    print(pem.decode())

except ImportError:
    print("ERROR: cryptography library not installed!")
    print("Run: pip install cryptography")
except Exception as e:
    print(f"ERROR extracting key: {e}")