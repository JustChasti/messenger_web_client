import json
from turtle import title
from flask import Blueprint, request, jsonify
from flask import render_template, redirect
from modules import forms


bp = Blueprint('views', __name__)


@bp.route("/test")
def test():
    return 'hello world'


@bp.route("/")
@bp.route("/home")
def home():
    return render_template('home.html', title='home')


@bp.route("/registration", methods=['GET', 'POST'])
def registration():
    form = forms.LoginForm()
    ermessage = ''
    if form.validate_on_submit():
        print(form.name.data, form.password.data)
        # creating new user
        return redirect('/')
    return render_template('registration.html', form=form, error=ermessage)
