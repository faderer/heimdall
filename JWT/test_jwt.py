import jwt
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa



def test_jwt():
    start_init = time.time()
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate public key
    public_key = private_key.public_key()

    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("Init used", time.time() - start_init)
    # key = "secret"
    start_encode = time.time()
    encoded = jwt.encode({"some": "payload"}, private_pem, algorithm="RS512")
    print("Encoding used", time.time() - start_encode)
    # print(encoded)
    start_decode = time.time()
    payload = jwt.decode(encoded, public_pem, algorithms="RS512")
    print("Decoding used", time.time() - start_decode)
    # print(payload)