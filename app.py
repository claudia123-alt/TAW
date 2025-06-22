from flask import Flask, render_template
from models import *

app = Flask(__name__)

def setup_database():
    if db.is_closed():
        db.connect()

setup_database()