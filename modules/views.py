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


keyPair = RSA.generate(1024)


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
    form = forms.LoginForm()
    ermessage = ''
    global keyPair
    public_key = keyPair.publickey()
    pubKey = public_key.exportKey().decode('ascii')
    privKey = keyPair.exportKey().decode('ascii')

    # print(pubKey, privKey)

    if form.validate_on_submit():
        # session['name'] = form.name.data
        # session['password'] = form.password.data
        # try:
        # sleep(1)
        # print(form.password.data)
        """
        ciphertext = base64.b64decode(form.password.data)
        cipher = PKCS1_OAEP.new(keyPair)
        print(ciphertext)
        # data_bytes = base64.b64decode(str(ciphertext).encode('utf-8'))
        # print(form.password.data)
        plain_text = cipher.decrypt(ciphertext)
        print(base64.b64encode(plain_text))
            # return redirect('/')
        # except Exception as e:
        #    ermessage = 'Ошибка - попытайтесь снова'
        """
    return render_template('login.html', form=form, error=ermessage, key=pubKey)


@bp.route("/jscipher", methods=['GET', 'POST'])
def jscipher():
    data = request.get_json(force=True)
    print(data)
    global keyPair
    ciphertext = base64.b64decode(data)
    cipher = PKCS1_v1_5.new(keyPair)
    plain_text = cipher.decrypt(ciphertext, 'bollox')
    print(plain_text, 'text')
    return (
        json.dumps({'info': 'ok'}),
        200,
        {'ContentType': 'application/json'}
    )
