import io

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

gSigner = "signer@cs-hva.nl"
vote_state_file = "vote.state"


def read_public():
    with open(gSigner+'.pub', 'rb') as key:
        serialized_pub_key = serialization.load_pem_public_key(
            key.read(),
            backend=default_backend()
        )
    return serialized_pub_key


def read_private():
    with open(gSigner+'.prv', 'rb') as key:
        serialized_prv_key = serialization.load_pem_private_key(
            key.read(),
            password=None,
            backend=default_backend()
        )
    return serialized_prv_key


def encrypt_state(state):
    if isinstance(state, io.StringIO):
        state = state.read()

    if not isinstance(state, bytes):
        state = bytes(state, encoding='utf-8')

    with open(state, 'rb') as state:
        votes = state.read()
    encrypted_votes = read_public().encrypt(
        votes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_votes


def write_encrypted_state():
    with open(vote_state_file, 'wb') as w_state:
        w_state.write(encrypt_state(vote_state_file))


def get_encrypted_state_file():
    with open(vote_state_file, 'rb') as r_state:
        encrypted_bytes = r_state.read()
    return encrypted_bytes


def decrypt_state_file():
    decrypted = read_private().decrypt(
        get_encrypted_state_file(),
        padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None,
                     )
    )
    return decrypted