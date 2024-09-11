import pyotp

# Dados de User Simulados
user_data = {
    'user1': {'password': 'password1', 'totp_secret': 'base32secret3232', 'hotp_counter': 1},
    'user2': {'password': 'password2', 'totp_secret': 'base32secret3232', 'hotp_counter': 2},
}


def authenticate_password(user_id, password):
    user = user_data.get(user_id)
    return user and user['password'] == password


def authenticate_totp(user_id, totp_code):
    user = user_data.get(user_id)
    if user:
        totp = pyotp.TOTP(user['totp_secret'])
        return totp.verify(totp_code)
    return False


def authenticate_hotp(user_id, hotp_code):
    user = user_data.get(user_id)
    if user:
        hotp = pyotp.HOTP(user['totp_secret'])
        if hotp.verify(hotp_code, user['hotp_counter']):
            user['hotp_counter'] += 1
            return True
    return False
