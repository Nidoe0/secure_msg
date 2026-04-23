import base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from verify import verify_signature

def decrypt_message(packet, private_key, sender_pub_key):

    raw = json.dumps({
        "enc_aes_key": packet["enc_aes_key"],
        "nonce": packet["nonce"],
        "ciphertext": packet["ciphertext"]
    }).encode()

    # Vérification AVANT déchiffrement Nidot
    if not verify_signature(raw, packet["signature"], sender_pub_key):
        raise ValueError("Signature invalide !")

    aes_key = private_key.decrypt(
        base64.b64decode(packet["enc_aes_key"]),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(aes_key)
    nonce = base64.b64decode(packet["nonce"])
    ciphertext = base64.b64decode(packet["ciphertext"])

    return aesgcm.decrypt(nonce, ciphertext, None).decode()