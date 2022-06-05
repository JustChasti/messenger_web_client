import json
from turtle import title
from flask import Blueprint, session, request, jsonify
from flask import render_template, redirect, url_for
from modules import forms
from time import sleep
from Cryptodome.PublicKey import RSA
from Crypto.Hash import SHA256
from Cryptodome.Cipher import PKCS1_v1_5, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
import base64


bp = Blueprint('views', __name__)
key_list = []


@bp.route("/test")
def test():
    return 'hello world'


@bp.route("/")
@bp.route("/home")
def home():
    print(session)
    return render_template('home.html', title='home')


@bp.route("/registration", methods=['GET', 'POST'])
def registration():
    form = forms.LoginForm()
    ermessage = ''
    if form.validate_on_submit():
        session['name'] = form.name.data
        session['password'] = form.password.data
        # creating new user
        try:
            pass
            # return redirect('/')
        except Exception as e:
            ermessage = 'Ошибка - попытайтесь снова'
    return render_template('registration.html', form=form, error=ermessage)


@bp.route("/login", methods=['GET', 'POST'])
def login():
    global key_list
    form = forms.LoginForm()
    ermessage = ''
    keyPair = RSA.generate(1024)
    public_key = keyPair.publickey()
    pubKey = public_key.exportKey().decode('ascii')
    key_list.append(
        {
            "public": pubKey,
            "key_pair": keyPair
        }
    )
    if form.validate_on_submit():
        return render_template('login.html', form=form, error=ermessage, key=pubKey)
    return render_template('login.html', form=form, error=ermessage, key=pubKey)


@bp.route("/jscipher", methods=['GET', 'POST'])
def jscipher():
    data = request.get_json(force=True)
    global key_list
    key_Pair = None
    print(key_list)
    for i in key_list:
        if data["public_key"][27:-25].replace("\n", "") == i["public"][27:-25].replace("\n", ""):
            key_Pair = i['key_pair']
            break
    if key_Pair:
        ciphertext = base64.b64decode(data["Ciphertext"])
        cipher = PKCS1_v1_5.new(key_Pair)
        plain_text = cipher.decrypt(ciphertext, 'bollox')
        print(plain_text, 'text')
        return (
            json.dumps({'info': 'ok'}),
            200,
            {'ContentType': 'application/json'}
        )
    else:
        print('not found', data["public_key"][27:-25])
        return (
            json.dumps({'info': 'keypain not found'}),
            200,
            {'ContentType': 'application/json'}
        )
