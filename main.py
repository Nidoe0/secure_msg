import argparse, json
from keygen import generate_rsa_keys
from encrypt import encrypt_message
from decrypt import decrypt_message
from sign import sign_message
from load_keys import load_private, load_public

parser = argparse.ArgumentParser()
parser.add_argument("--action", required=True, choices=["keygen", "send", "receive"])
parser.add_argument("--msg")
parser.add_argument("--packet")

args = parser.parse_args()

if args.action == "keygen":
    generate_rsa_keys()

elif args.action == "send":
    priv = load_private("private.pem")
    pub = load_public("public.pem")

    pkt = encrypt_message(args.msg, pub)

    raw = json.dumps({
        "enc_aes_key": pkt["enc_aes_key"],
        "nonce": pkt["nonce"],
        "ciphertext": pkt["ciphertext"]
    }).encode()

    pkt["signature"] = sign_message(raw, priv)

    print(json.dumps(pkt, indent=2))

elif args.action == "receive":
    priv = load_private("private.pem")
    pub = load_public("public.pem")

    with open(args.packet) as f:
        pkt = json.load(f)

    msg = decrypt_message(pkt, priv, pub)
    print("Message reçu :", msg)