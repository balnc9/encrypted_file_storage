import os
# test scripts from in-person guided lab sections
# just use as samples for real scripts i suppose

'''
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms,modes


key = os.urandom(32)
iv = os.urandom(16)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(b"Secret Message #1") + encryptor.finalize()
decryptor = cipher.decryptor()
dec = decryptor.update(ct) + decryptor.finalize()

print(dec)
'''


from cryptography.fernet import Fernet
key = Fernet.generate_key()
f = Fernet(key)
tok = f.encrypt(b"secret message 2")
print(tok)

print(f.decrypt(tok))
