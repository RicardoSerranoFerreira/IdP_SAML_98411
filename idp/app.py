import os
import json
import logging
from flask import Flask, request, redirect, session, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
from saml2 import config as saml_config
from saml2 import server as saml_server
from saml2.saml import NameID, AuthnRequest
from saml2.sigver import SAMLError
import pyotp
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random
import saml_config

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///idp.db'
db = SQLAlchemy(app)

# Logging setup
logging.basicConfig(level=logging.INFO)

# User, falta fazer roles
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    roles = db.Column(db.String(120), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=True)
    hotp_secret = db.Column(db.String(16), nullable=True)

# Serviço, por alterar
class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    attributes = db.Column(db.Text, nullable=False)
    penalty = db.Column(db.Integer, nullable=False)
    min_auth_methods = db.Column(db.Integer, nullable=False)
    saml_response_url = db.Column(db.String(200), nullable=False)
@app.before_first_request
def create_tables():
    db.create_all()

    # Add initial data for Service Providers
    sp1 = ServiceProvider(
        name= 'Serviço 1',
        public_key=open('certs/sp_cert.pem').read(),
        metadata_url='http://localhost:5001/saml/metadata',
        penalty_value=5,
        min_auth_methods=1,
        response_url='http://localhost:5001/saml/acs'
    )
    db.session.add(sp1)

    # Add initial data for Users
    user1 = User(
        username='testuser',
        password_hash=generate_password_hash('password123'),
        otp_secret='JBSWY3DPEHPK3PXP',
        hotp_secret='JBSWY3DPEHPK3PXP'
    )
    db.session.add(user1)
    db.session.commit()
def authenticate_user(username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.password == password:
        return user
    return None
def handle_mfa(user, service):
    risk_score = get_user_risk_score(user) + service.penalty
    auth_methods_needed = max(service.min_auth_methods, (risk_score // 10))
    methods = ['password']
    if auth_methods_needed >= 4:
        methods += ['totp', 'hotp', 'hardware']
    elif auth_methods_needed == 3:
        methods += ['totp', 'hotp']
    elif auth_methods_needed == 2:
        methods += ['totp']

    return methods

# Valor random para score de risco
def get_user_risk_score(user):
    return random.randint(0, 50)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = authenticate_user(username, password)
        if user:
            session['user_id'] = user.id
            return redirect(url_for('sso'))
        return 'Invalid credentials', 401
    return render_template('login.html')


@app.route('/sso')
def sso():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    service = Service.query.first()  # Dado que existe apenas 1

    mfa_methods = handle_mfa(user, service)

    if 'totp' in mfa_methods and not verify_totp(user):
        return redirect(url_for('totp'))

    if 'hotp' in mfa_methods and not verify_hotp(user):
        return redirect(url_for('hotp'))

    if 'hardware' in mfa_methods and not verify_hardware(user):
        return redirect(url_for('hardware'))

    saml_response = generate_saml_response(user, service)
    return saml_response


def verify_totp(user):
    if not user.otp_secret:
        return False
    otp = request.form.get('otp')

    totp = pyotp.TOTP(user.otp_secret)
    return totp.verify(otp)


def verify_hotp(user):
    if not user.hotp_secret:
        return False
    otp = request.form.get('otp')

    counter = request.form.get('counter', type=int)

    hotp = pyotp.HOTP(user.hotp_secret)
    return hotp.verify(otp, counter)

# Retorna True por propósito de teste
def verify_hardware(user):
    return True

@app.route('/totp', methods=['GET', 'POST'])
def totp():
    if request.method == 'POST':
        if verify_totp(User.query.get(session['user_id'])):
            return redirect(url_for('sso'))
        return 'Invalid TOTP', 401
    return render_template('totp.html')

@app.route('/hotp', methods=['GET', 'POST'])
def hotp():
    if request.method == 'POST':
        if verify_hotp(User.query.get(session['user_id'])):
            return redirect(url_for('sso'))
        return 'Invalid HOTP', 401
    return render_template('hotp.html')

@app.route('/hardware', methods=['GET', 'POST'])
def hardware():
    if request.method == 'POST':
        if verify_hardware(User.query.get(session['user_id'])):
            return redirect(url_for('sso'))
        return 'Invalid Hardware MFA', 401
    return render_template('hardware.html')

@app.route('/metadata')
def metadata():
    saml_config = get_saml_config()
    metadata = saml_config.metadata
    return metadata


if __name__ == '__main__':
    app.run(debug=True)
