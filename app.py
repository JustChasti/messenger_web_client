from flask import Flask
from flask_bootstrap import Bootstrap
from modules import views


application = Flask(__name__)
application.testing = True
application.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


if __name__ == "__main__":
    Bootstrap(application)
    application.register_blueprint(views.bp)
    application.run(debug=True)
