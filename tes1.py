from urllib import response
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.Random import get_random_bytes
import base64
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
import hashlib
import uuid

import requests
import json

"""
-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmzbPdc0zZclXXdHTBCde4CFfD\n3M6ejqzNUnCfa46lEKO8+41IQJuWBVCXebjpkcBZydKqlcvSfkK1p9gnCzx2lCjs\n6gC9sIPt1vuLBd8MxlRlcrPzku+3TU6xkdIb6AZCe9W6c6hW+9H+uOi5qdKZtggq\nChfKhMkGkO9790XeYQIDAQAB\n-----END PUBLIC KEY-----"
"""


def ecryptor(text, key):
    dat = key.encrypt(str(text).encode('utf-8'), padding.PKCS1v15())
    return base64.b64encode(dat).decode('ascii')


def get_token(operation_id, username, keyPair, random_str, server_key):
    """
        operation_id - id операции там для реги 0 и тд
        random_str - надо генерить новую перед каждым запросом
    """
    url = 'http://178.21.10.180/getconfurm'
    client_key = keyPair.publickey()

    data = {
        "operationId": str(ecryptor(operation_id, server_key)),
        "hashName": ecryptor(
            hashlib.md5(str.encode(username)).hexdigest().upper(),
            server_key
        ),
        "confurmStringClient": str(ecryptor(random_str, server_key)),
        "openkey": str(client_key.exportKey().decode('ascii'))
    }
    response = requests.post(url=url, json=data)
    token = response.json()["serverToken"]
    sentinel = get_random_bytes(20)
    cipher = PKCS1_v1_5.new(keyPair)
    plain_text = cipher.decrypt(
        base64.b64decode(str(token).encode('utf-8')),
        sentinel
    )
    return plain_text.decode("utf-8").split('|')[1]


def registration(username, password, keypair, server_key):
    url = 'http://178.21.10.180/registration'
    random_str = str(uuid.uuid4())
    server_token = get_token(
        operation_id=0,
        username=username,
        keyPair=keypair,
        random_str=random_str,
        server_key=server_key
    )
    user_name = ecryptor(f'{server_token}|{username}|{random_str}', server_key)
    user_pass = ecryptor(f'{random_str}|{password}|{server_token}', server_key)
    data = {
        "name": user_name,
        "openkey": str(keypair.publickey().exportKey().decode('ascii')),
        "password": user_pass
    }
    response = requests.post(url=url, json=data)
    token = response.json()['token']
    cipher = PKCS1_v1_5.new(keyPair)
    sentinel = get_random_bytes(20)
    plain_text = cipher.decrypt(
        base64.b64decode(str(token).encode('utf-8')),
        sentinel
    )
    return plain_text.decode("utf-8").split('|')[1]


def send_message(username, recipient, text, token, keypair, server_key):
    url = 'http://178.21.10.180/'
    random_str = str(uuid.uuid4())
    server_token = get_token(
        operation_id=2,
        username=username,
        keyPair=keypair,
        random_str=random_str,
        server_key=server_key
    )
    recipient_url = f'{url}getuserkeypem?recipient={recipient}'
    recipient_key = requests.get(url=recipient_url).json()['openkey']  # x
    print(recipient_key)
    recipient_key = load_pem_public_key(
        str.encode(recipient_key),
        backend=default_backend()
    )
    en_message = ecryptor(f'{username}|{text}', recipient_key)
    hash = hashlib.md5(str.encode(f'{token}{en_message}{server_token}')).hexdigest().upper()
    data = {
        'sender': hashlib.md5(str.encode(username)).hexdigest().upper(),
        'recipient': hashlib.md5(str.encode(recipient)).hexdigest().upper(),
        'hash': hash,
        'messageText': en_message
    }
    response = requests.post(url=f'{url}sendmessage', json=data)
    print(response.json())


keyPair = RSA.generate(1024)
server_key = load_pem_public_key(
        open('server_public.pem').read().encode(),
        backend=default_backend()
)
# token = registration('test', 'qwerty', keyPair, server_key)
# print(token)
token = 'b0e083ad-d5bc-4444-a07b-c6a90e6db5f0'
send_message('test', 'gfd', '121231sdfgss', token, keyPair, server_key)
