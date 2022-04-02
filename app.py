from flask import Flask
from modules import views


application = Flask(__name__)


if __name__ == "__main__":
    application.register_blueprint(views.bp)
    application.run(debug=True)
