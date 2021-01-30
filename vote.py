#!/usr/bin/env python

import sys, os
import getopt
import io
import csv
import datetime
import collections
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

import state_handler
gDbg = False
gSigner = "signer@cs-hva.nl"


def sign(data, signer=gSigner, sfx='.prv'):
    if isinstance(data, io.StringIO):
        data = data.read()

    if not isinstance(data, bytes):
        data = bytes(data, encoding='utf-8')

    sign = b''

    with io.open(signer+'.prv', "rb") as fp:
        prvKey = serialization.load_pem_private_key(fp.read(), password=None)
    sign = prvKey.sign(data, padding.PKCS1v15(), hashes.SHA256())

    return ':'.join(['#sign', 'sha256-PKCS1-rsa2048', signer, sign.hex()])


def verify(data, signature, signer=gSigner, sfx='.pub'):
    if isinstance(data, io.StringIO):
        data = data.read()

    if not isinstance(data, bytes):
        data = bytes(data, encoding='utf-8')

    flds = signature.split(':')

    if flds[1] != 'sha256-PKCS1-rsa2048' and flds[2] != signer:
        print('Error: Unknown signature:', signature)
        return None
    sign = bytes.fromhex(flds[3])

    res = False
    # Validate the signature of the data using a prvKey, sha256, pkcs1 en rsa-2048
    # Student Work {{
    with io.open(signer+'.pub', "rb") as fp:
        pubKey = serialization.load_pem_public_key(fp.read())
    try:
        sign = bytes.fromhex(flds[3])
        pubKey.verify(
            sign,
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        res = True
    except Exception as e:
        print('Exception', e)
        res = False
    # Student Work }}

    return res


def load_file(fname, useSign=True, signer=gSigner):
    """ Load file check signature """
    data = io.open(fname, 'r', encoding='UTF-8').read()
    n = data.find('#sign')
    if n > 0:
        sign = data[n:].strip()
        data = data[0:n]
        if useSign:
            res = verify(data, sign, signer, sfx='.pub')
            if not res: return None
    return io.StringIO(data)


def save_file(fname, data, useSign=True, signer=gSigner):
    """ Save file check signature """
    if isinstance(data, io.StringIO): data = data.read()
    n = data.find('#sign')
    if n > 0:
        data = data[0:n]
    if useSign:
        data += sign(data, signer) + '\n'
    io.open(fname, 'w', encoding='UTF-8').write(data)
    return


def load_voters(fname):
    try:
        voters = { s['studNr']: s for s in csv.DictReader(load_file(fname), delimiter=';') }
        return voters
    except Exception as e:
        return {}


def load_candidates(fname):
    try:
        candidates = {s['mdwId']: s for s in csv.DictReader(load_file(fname), delimiter=';') }
        return candidates
    except Exception as e:
        return {}

# This is non-secure version of Voting.
# Make it more secure
# Does ir follow your Constrains (Randvoorwaarden)


class Vote:
    _voters = []
    _casts = []

    def __init__(self):
        fname = 'vote'+'.state'
        if os.path.exists(fname):
            # Recover saved state
            state_handler.decrypt_state_file()
            jDct = json.load(io.open(fname, 'r'))
            self._voters = jDct['voters']
            self._casts = jDct['casts']
            if gDbg: print('DEBUG: recovered state:', fname)

    def __del__(self):
        # Save state
        fname = 'vote'+'.state'
        jDct = {'voters': self._voters, 'casts':  self._casts}
        json.dump(jDct, io.open(fname, 'w'))
        state_handler.encrypt_state_file()
        if gDbg:
            print('DEBUG: saved state:', fname)

    def vote(self, voteId, candId):
        # Do some checks about voters and candidates
        # StudentWork {{
        if voteId in self._voters:
            print('Error: Mutiple vote: {}'.format(voteId))
        # StudentWork }}
        now = datetime.datetime.now()

        if voteId in gVoters and candId in gCandidates:
            self._voters.append(voteId)
            self._casts.append(candId)
        return f'Voter: {voteId} voted {candId} at {now}'

    def results(self):
        votes = collections.Counter(self._casts)
        return votes.most_common()

    def audit(self):
        save_file('audit_cand.json', json.dumps(self._casts))
        save_file('audit_vote.json', json.dumps(self._voters))
        if gDbg:
            print("DEBUG: saved audit-trail")

    def create(self):
        # Reinitialize state
        self._voters = []
        self._casts = []

        fname = 'vote'+'.state'
        if os.path.exists(fname):
            os.remove(fname)

    def delete(self):
        # Reinitialize state
        self._voters = []
        self._casts = []

        fname = 'vote'+'.state'
        if os.path.exists(fname):
            os.remove(fname)

    def stats(self):
        return {
                'candidates': len(gCandidates),
                'registrated': len(gVoters),
                'voters': len(self._voters),
                'casts': len(self._casts),
        }


gVoters = load_voters('voters.csv')
gCandidates = load_candidates('candidates.csv')
if __name__ == '__main__':
    cmd = ''
    opts, args = getopt.getopt(sys.argv[1:], 'hp:c:', [ 'create', 'vote', 'res', 'stat', 'delete' ])
    for opt, arg in opts:
        if opt == '-h':
            print('Usage: vote --create')
            print('\tInitialize vote system')
            print('Usage: vote --vote -p <voteId> -c <candId>')
            print('\tCast vote')
            print('Usage: vote --res')
            print('\tShow results')
            print('Usage: vote --stat')
            print('\tShow statistics')
            print('Usage: vote --delete')
            print('\tDelete all information (securily)')
            sys.exit()
        if opt == '-D': gDbg = True

        if opt == '-p': voteId = arg
        if opt == '-c': candId = arg
        if opt[0:2] == '--': cmd = opt[2:]

    voting = Vote()
    if cmd == 'create':
        voting.create()
    if cmd == 'vote':
        reciept = voting.vote(voteId, candId)
        if reciept:
            print(reciept)
    if cmd == 'res':
        voting.audit()
        for res in voting.results()[:3]:
            print('{0:3s}: {1:3d}'.format(res[0], res[1]))
    if cmd == 'stat':
        print(voting.stats())
    if cmd == 'delete':
        voting.delete()

    # force saving state
    voting = None
