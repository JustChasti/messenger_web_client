from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
import base64

"""
key = RSA.import_key(open('public.pem').read())
msg = b'Hello, this is the demo of encryption/decryption in javascript!'
encryptor = PKCS1_OAEP.new(key)
encrypted = encryptor.encrypt(msg)
ciphertext = base64.b64encode(encrypted)
print(ciphertext)

js_str = "cHbYXESgngA50TZxmFmKVW3pd+lKGLJkTK3pNAVFDYe2eM8DGnuZG8XRoGQsv0BlYCtgjhKfcY6LVLGPg8b2SFuw92mqvwMXygZ3bdd2Ld6NzkGb6QWTAHJ9yCUogA8at8PRCoDPeY3a4/bo1AYCwd/vOVuJke9Wwrv+K8+Sjsg="
py_str = b"kAr7IzDisd\CZCB0nolawovb7OmfG3uzj+j6a+xRdLBEbMjXEiAzoz\sUYOR6leIPaFDvVM20r++JyoQztCktq6C711mOtSCyHNHw3SEP+oDDWTdvcyZHVzP2OYntNXFrwj2hSzF8MYEmn3WZgv0bQQ0Jp62nps5bSVZHZwUj6E="


key = RSA.import_key(open('private.pem').read())
cipher = PKCS1_OAEP.new(key)
plain_text = cipher.decrypt(ciphertext)
print(plain_text.decode("utf-8"))
"""
# js_str = b"cHbYXESgngA50TZxmFmKVW3pd+lKGLJkTK3pNAVFDYe2eM8DGnuZG8XRoGQsv0BlYCtgjhKfcY6LVLGPg8b2SFuw92mqvwMXygZ3bdd2Ld6NzkGb6QWTAHJ9yCUogA8at8PRCoDPeY3a4/bo1AYCwd/vOVuJke9Wwrv+K8+Sjsg="
# print(base64.b64decode(js_str))


keyPair = RSA.generate(1024)
public_key = keyPair.publickey()
# pubKey= public_key.exportKey().decode('ascii')
# privKey = keyPair.exportKey().decode('ascii')

msg = b'Hello, this is the demo of encryption/decryption in javascript!'
encryptor = PKCS1_OAEP.new(public_key)
encrypted = encryptor.encrypt(msg)
ciphertext = base64.b64encode(encrypted)
print(ciphertext)
decryptor = PKCS1_OAEP.new(keyPair)
decrypted = decryptor.decrypt(base64.b64decode(ciphertext))
print('Decrypted:', decrypted)
