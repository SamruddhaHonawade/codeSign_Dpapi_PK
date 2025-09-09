# hashing.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def compute_sha3_256(data: bytes) -> bytes:
    """Computes the SHA3-256 hash of the given data."""
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def compute_sha3_512(data: bytes) -> bytes:

    digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    digest.update(data)
    return digest.finalize()
