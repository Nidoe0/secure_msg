from cryptography.hazmat.primitives import serialization

def load_private(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())