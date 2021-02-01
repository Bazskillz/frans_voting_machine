import io
import os
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

import integrity_tools

gSigner = "signer@cs-hva.nl"
vote_state_file = "vote.state"


def read_casts():
    json_dict = json.load(io.open(vote_state_file, 'r'))
    return json_dict['casts']


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


def write_encrypted_state():
    if os.path.exists(vote_state_file):
        with io.open(vote_state_file, 'rb') as read_state:
            encrypted_state_bytes = read_public().encrypt(read_state.read(),
                                                          padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                       algorithm=hashes.SHA256(), label=None))
        with io.open(vote_state_file, 'wb') as write_state:
            write_state.write(encrypted_state_bytes)
    integrity_tools.update_hash_file()


def decrypt_state_file():
    decrypted_state_bytes = []
    if os.path.exists(vote_state_file):
        with io.open(vote_state_file, 'rb') as read_state:
            encrypted_bytes = read_state.read()
            decrypted_state_bytes = read_private().decrypt(
                encrypted_bytes,
                padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None,
                             )
            )
    with io.open(vote_state_file, 'wb') as write_state:
        write_state.write(decrypted_state_bytes)

