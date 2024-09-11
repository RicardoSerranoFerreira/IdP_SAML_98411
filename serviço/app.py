from flask import Flask, session, render_template, redirect, url_for

app = Flask(__name__)
app.secret_key = 'service_secret_key'

@app.route('/')
def index():
    user_id = session.get('user_id')
    if user_id:
        return render_template('protected.html', user_id=user_id)
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    return redirect('http://localhost:5000/saml/login')


@app.route('/saml/acs', methods=['POST'])
def acs():
    # Handle SAML Assertion Consumer Service (ACS) endpoint here
    # Parse the SAML response and extract the user information
    session['user_id'] = 'extracted_user_id_from_saml'
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True, port=5001)
