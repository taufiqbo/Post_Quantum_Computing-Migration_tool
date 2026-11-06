"""Sample that hides its crypto behind nicknames. Regex misses most of it."""
from Crypto.Cipher import DES3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa as r

old_key = r.generate_private_key(public_exponent=65537, key_size=1024)
digest = hashes.Hash(hashes.SHA1())
cipher = DES3.new(secret, DES3.MODE_CBC)