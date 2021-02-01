import io
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

gSigner = "signer@cs-hva.nl"


def read_public():
    """
    Returns serialized public key object.
    @return: serialized public key object
    """
    with open(gSigner+'.pub', 'rb') as key:
        serialized_pub_key = serialization.load_pem_public_key(
            key.read(),
            backend=default_backend()
        )
    return serialized_pub_key


def read_private():
    """
    Returns serialized private key object.
    @return: serialized private key object
    """
    with open(gSigner+'.prv', 'rb') as key:
        serialized_prv_key = serialization.load_pem_private_key(
            key.read(),
            password=None,
            backend=default_backend()
        )
    return serialized_prv_key


def sign_data(data, signer=gSigner):
    """
    @param data: the input data for the signing
    @param signer: The signing entity
    @return: hexadecimal notation of the SHA256 signature calculated over the input data
    """
    if isinstance(data, io.StringIO):
        data = data.read()

    if not isinstance(data, bytes):
        data = bytes(data, encoding='utf-8')

    signature = b''
    signature = read_private().sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signature.hex()


def create_state_hash():
    """
    returns hexadecimal sha256 signature of vote.state
    @return: hexadecimal sha256 signature of vote.state
    """
    vote_state = b''
    if os.path.exists('vote.state'):
        with io.open('vote.state', 'rb') as read_state:
            vote_state = read_state.read()
    return sign_data(data=vote_state)


def update_hash_file():
    """
    Writes the sha256 signature of vote.state to vote_state.hash
    """
    state_hash = create_state_hash()
    with io.open('vote_state.hash', 'w') as write_hash:
        write_hash.write(state_hash)
