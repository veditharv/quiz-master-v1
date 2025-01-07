from flask import Flask, redirect, request, render_template, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main_database.sqlite3'
db = SQLAlchemy()
db.init_app(app)
app.app_context().push()
