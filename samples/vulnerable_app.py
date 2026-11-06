"""Deliberately insecure sample for testing the scanner."""
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dh

def make_keys():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
    return rsa_key, ec_key, dh_parameters

def fingerprint(data) :
    return hashlib.md5(data).hexdigest()

def legacy_hash(data):
    return hashlib.sha1(data).hexdigest()

def good_hash(data):
    return hashlib.sha3_256(data).hexdigest()