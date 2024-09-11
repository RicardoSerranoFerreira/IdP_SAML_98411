import os
import logging
from flask import Flask, request, session, redirect, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///service.db'
db = SQLAlchemy(app)

# Logging setup
logging.basicConfig(level=logging.INFO)

# Define models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Documento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)

@app.before_first_request
def create_tables():
    db.create_all()

    # Dados para documento random
    dc1 = ServiceProvider(
        name= 'Documento - User 1',
        title= 'Info Random',
        content= "Informação sobre tópicos atuais: **"
    )
    db.session.add(dc1)

    # Dados para User
    user1 = User(
        username='testuser',
        password= 'password123'
    )
    db.session.add(user1)
    db.session.commit()
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/protected')
def protected():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    documents = Documento.query.filter_by(user_id=user.id).all()
    return render_template('protected.html', documents=documents)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            return redirect(url_for('protected'))
        return 'Invalid credentials', 401
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True, port=5001)
