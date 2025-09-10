from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_keypair(algo: str, key_param: str):
    try:
        if algo == "RSA":
            key_size = int(key_param)
            return rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
        elif algo == "ECDSA":
            if key_param == "SECP256R1":
                curve = ec.SECP256R1()
            elif key_param == "SECP384R1":
                curve = ec.SECP384R1()
            elif key_param == "SECP521R1":
                curve = ec.SECP521R1()
            else:
                raise ValueError(f"Unsupported curve: {key_param}")
            return ec.generate_private_key(curve, backend=default_backend())
        raise ValueError(f"Unsupported algorithm: {algo}")
    except Exception as e:
        raise ValueError(f"Failed to generate keypair for {algo}: {str(e)}")

def load_private_key(key_path: str, password: bytes = None):
    try:
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
                backend=default_backend()
            )
        return private_key
    except Exception as e:
        raise ValueError(f"Failed to load key from {key_path}: {str(e)}")

def sign_digest(private_key, algo: str, digest: bytes, hash_algo: str = "sha3_256") -> bytes:
    """Signs a digest using the provided private key and algorithm."""
    try:
        hash_class = hashes.SHA3_256 if hash_algo == "sha3_256" else hashes.SHA3_512
        if algo == "RSA":
            return private_key.sign(
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hash_class()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_class()
            )
        elif algo == "ECDSA":
            return private_key.sign(digest, ec.ECDSA(hash_class()))
        raise ValueError(f"Unsupported algorithm: {algo}")
    except Exception as e:
        raise ValueError(f"Failed to sign digest with {algo}: {str(e)}")

def verify_signature(public_key, algo: str, digest: bytes, signature: bytes, hash_algo: str = "sha3_256") -> bool:
    """Verifies a signature against a digest using the public key."""
    try:
        hash_class = hashes.SHA3_256 if hash_algo == "sha3_256" else hashes.SHA3_512
        if algo == "RSA":
            public_key.verify(
                signature,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hash_class()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_class()
            )
        elif algo == "ECDSA":
            public_key.verify(signature, digest, ec.ECDSA(hash_class()))
        return True
    except Exception:
        return False
