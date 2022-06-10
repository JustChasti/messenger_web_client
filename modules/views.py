import json
from flask import Blueprint, request
from flask import render_template, redirect, url_for, make_response
from modules import forms
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
import base64

from modules import servereqs
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend


bp = Blueprint('views', __name__)
key_list = []
user_data = []


server_key = load_pem_public_key(
        open('server_public.pem').read().encode(),
        backend=default_backend()
)


@bp.route("/test")
def test():
    return 'hello world'


@bp.route("/", methods=['GET', 'POST'])
@bp.route("/home", methods=['GET', 'POST'])
def home():
    global user_data
    form = forms.MessageSendForm()
    user_token = request.cookies.get('user_token')
    username = request.cookies.get('username')
    print(user_token, username)
    profile = None
    for i in user_data:
        if i['username'] == username:
            profile = i
    if not profile:
        return("Not autorized")
    profile['username']
    messages = None
    try:
        messages = servereqs.get_messages(
            profile['username'],
            user_token,
            profile['key_pair'],
            server_key
        )
    except Exception as e:
        page_info = 'Ошибка получения сообщений'
    if not messages:
        messages = []
    if form.validate_on_submit():
        try:
            servereqs.send_message(
                profile['username'],
                form.recipient.data,
                form.text.data,
                user_token,
                profile['key_pair'],
                server_key
            )
            page_info = 'Сообщение отправлено'
        except Exception as e:
            page_info = 'Сообщение не отправлено'
        return render_template(
            'home.html',
            messages=messages,
            form=form,
            message=page_info
        )
    return render_template(
        'home.html',
        messages=messages,
        form=form,
        message=''
    )


@bp.route("/registration", methods=['GET', 'POST'])
def registration():
    global key_list
    form = forms.LoginForm()
    ermessage = ''
    keyPair = RSA.generate(1024)
    public_key = keyPair.publickey()
    pubKey = public_key.exportKey().decode('ascii')
    key_list.append(
        {
            "public": pubKey,
            "key_pair": keyPair,
        }
    )
    if request.method == 'POST':
        return redirect(url_for('views.home'))
    return render_template(
        'registration.html',
        form=form,
        error=ermessage,
        key=pubKey
    )


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
            "key_pair": keyPair,
        }
    )
    if request.method == 'POST':
        return redirect(url_for('views.home'))
    return render_template(
        'login.html',
        form=form,
        error=ermessage,
        key=pubKey
    )


@bp.route("/jsautorize", methods=['GET', 'POST'])
def jsautorize():
    data = request.get_json(force=True)
    global key_list
    global user_data
    key_Pair = None
    for i in key_list:
        if data["public_key"][27:-25].replace("\n", "") == i["public"][27:-25].replace("\n", ""):
            key_Pair = i['key_pair']
            break
    if key_Pair:
        ciphertext = base64.b64decode(data["ciphertext"])
        cipher = PKCS1_v1_5.new(key_Pair)
        plain_text = cipher.decrypt(ciphertext, 'bollox')
        password = plain_text.decode("utf-8")
        user_token = None
        try:
            user_token = servereqs.authorization(data["username"], password, key_Pair, server_key)
            for i in user_data:
                if i['username'] == data["username"]:
                    user_data.remove(i)
            user_data.append({
                "username": data["username"],
                "password": password,
                "key_pair": key_Pair
            })
        except Exception as e:
            print(e)
        if user_token:
            resp = make_response("The Cookie has been set")
            resp.set_cookie('user_token', user_token)
            resp.set_cookie("username", data["username"])
        return resp

    else:
        print('not found', data["public_key"][27:-25])
        return (
            json.dumps({'info': 'keypain not found'}),
            200,
            {'ContentType': 'application/json'}
        )


@bp.route("/jsregistr", methods=['GET', 'POST'])
def jsregistr():
    data = request.get_json(force=True)
    global key_list
    global user_data
    key_Pair = None
    for i in key_list:
        if data["public_key"][27:-25].replace("\n", "") == i["public"][27:-25].replace("\n", ""):
            key_Pair = i['key_pair']
            break
    if key_Pair:
        ciphertext = base64.b64decode(data["ciphertext"])
        cipher = PKCS1_v1_5.new(key_Pair)
        plain_text = cipher.decrypt(ciphertext, 'bollox')
        password = plain_text.decode("utf-8")
        user_token = None
        try:
            user_token = servereqs.registration(data["username"], password, key_Pair, server_key)
            for i in user_data:
                if i['username'] == data["username"]:
                    user_data.remove(i)
            user_data.append({
                "username": data["username"],
                "password": password,
                "key_pair": key_Pair
            })
        except Exception as e:
            print(e)
        if user_token:
            resp = make_response("The Cookie has been set")
            resp.set_cookie('user_token', user_token)
            resp.set_cookie("username", data["username"])
            return resp

    else:
        print('not found', data["public_key"][27:-25])
        return (
            json.dumps({'info': 'keypain not found'}),
            200,
            {'ContentType': 'application/json'}
        )
