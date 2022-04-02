import json
from logging import exception
from turtle import title
from flask import Blueprint, request, jsonify, render_template


bp = Blueprint('views', __name__)


@bp.route("/test")
def test():
    return 'hello world'


@bp.route("/")
@bp.route("/home")
def home():
    return render_template('home.html', title='home')
