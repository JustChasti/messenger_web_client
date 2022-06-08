from lib2to3.pgen2 import token
from logging import exception
from urllib import response
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.Random import get_random_bytes
import base64
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import hashlib
import uuid

import requests


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
    recipient_key = load_pem_public_key(
        str.encode(recipient_key),
        backend=default_backend()
    )
    en_message = ecryptor(f'{username}|{text}', recipient_key)
    hash = hashlib.md5(
        str.encode(f'{token}{en_message}{server_token}')
    ).hexdigest().upper()
    data = {
        'sender': hashlib.md5(str.encode(username)).hexdigest().upper(),
        'recipient': hashlib.md5(str.encode(recipient)).hexdigest().upper(),
        'hash': hash,
        'messageText': en_message
    }
    response = requests.post(url=f'{url}sendmessage', json=data)
    print(response.json())


def authorization(username, password, keypair, server_key):
    url = 'http://178.21.10.180/authorization'
    random_str = str(uuid.uuid4())
    server_token = get_token(
        operation_id=1,
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


def get_messages(username, token, keypair, server_key):
    url = 'http://178.21.10.180/getmessages'
    random_str = str(uuid.uuid4())
    server_token = get_token(
        operation_id=3,
        username=username,
        keyPair=keypair,
        random_str=random_str,
        server_key=server_key
    )
    hash_name = hashlib.md5(str.encode(username)).hexdigest().upper()
    hash = hashlib.md5(
        str.encode(f'{token}{hash_name}{server_token}')
    ).hexdigest().upper()
    data = {
        'name': hashlib.md5(str.encode(username)).hexdigest().upper(),
        'openkey': str(keypair.publickey().exportKey().decode('ascii')),
        'hashkey': hash,
    }
    response = requests.post(url=url, json=data)
    try:
        messages = response.json()['gettedmessages']
    except exception as e:
        print(e)
    if messages:
        print(messages)
        cipher = PKCS1_v1_5.new(keyPair)
        sentinel = get_random_bytes(20)
        for i in messages.split('#'):
            print(str(i.split('|')[-1]))
            plain_text = cipher.decrypt(
                base64.b64decode(str(i.split('|')[-1]).encode('utf-8')),
                sentinel
            )
            print(plain_text.decode("utf-8"))
    """
    token = response.json()['token']
    cipher = PKCS1_v1_5.new(keyPair)
    sentinel = get_random_bytes(20)
    plain_text = cipher.decrypt(
        base64.b64decode(str(token).encode('utf-8')),
        sentinel
    )
    return plain_text.decode("utf-8").split('|')[1]
    """


keyPair = RSA.generate(1024)
keyPair1 = RSA.generate(1024)
server_key = load_pem_public_key(
        open('server_public.pem').read().encode(),
        backend=default_backend()
)

token1 = authorization('test', 'qwerty', keyPair, server_key)

token = 'c244d66c-1d66-4060-90be-7e49ee9d6e67'
send_message('test1', 'test', 'test message 2', token, keyPair, server_key)

get_messages('test', token1, keyPair, server_key)

# token = registration('test1', 'qwerty', keyPair, server_key)
# print(token)
