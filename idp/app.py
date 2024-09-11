from flask import Flask, redirect, session, render_template, request, jsonify, url_for
from flask_saml2.sp import ServiceProvider
from models import RegisteredService
from mfa import authenticate_password, authenticate_totp, authenticate_hotp
from saml_config import MyServiceProvider, registered_services

app = Flask(__name__)
app.secret_key = 'idp_secret_key'

# Register the SAML ServiceProvider
sp = MyServiceProvider()
app.register_blueprint(sp.create_blueprint(), url_prefix='/saml')


@app.route('/register_service', methods=['POST'])
def register_service():
    data = request.json
    service_id = data.get('service_id')
    public_key = data.get('public_key')
    identity_attributes = data.get('identity_attributes')
    penalty = data.get('penalty')
    min_auth_methods = data.get('min_auth_methods')
    saml_response_url = data.get('saml_response_url')

    if service_id and public_key and saml_response_url:
        registered_services[service_id] = RegisteredService(
            public_key, identity_attributes, penalty, min_auth_methods, saml_response_url)
        return jsonify({"status": "Service registered successfully"}), 200

    return jsonify({"error": "Invalid data"}), 400


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']
        service_id = request.form['service_id']

        if authenticate_password(user_id, password):
            session['user_id'] = user_id
            return redirect(url_for('mfa', service_id=service_id))

        return 'Invalid credentials', 401

    return render_template('login.html')


@app.route('/mfa/<service_id>', methods=['GET', 'POST'])
def mfa(service_id):
    user_id = session.get('user_id')

    if not user_id:
        return redirect(url_for('login'))

    # Determine the number of MFA steps needed
    service = registered_services.get(service_id)
    mfa_methods = sp.determine_mfa_methods(service_id, user_id)

    if mfa_methods >= 2 and 'mfa_totp' not in session:
        if request.method == 'POST':
            totp = request.form.get('totp')
            if authenticate_totp(user_id, totp):
                session['mfa_totp'] = True
                return redirect(url_for('mfa', service_id=service_id))

        return render_template('totp.html')

    if mfa_methods >= 3 and 'mfa_hotp' not in session:
        if request.method == 'POST':
            hotp = request.form.get('hotp')
            if authenticate_hotp(user_id, hotp):
                session['mfa_hotp'] = True
                return redirect(url_for('mfa', service_id=service_id))

        return render_template('hotp.html')

    # Dar redirect, se passar o MFA
    sp.login_successful(user_id)
    return redirect(sp.get_saml_response_url(service_id))


if __name__ == '__main__':
    app.run(debug=True, port=5000)
