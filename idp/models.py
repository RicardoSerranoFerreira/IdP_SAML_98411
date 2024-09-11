class RegisteredService:
    def __init__(self, public_key, identity_attributes, penalty, min_auth_methods, saml_response_url):
        self.public_key = public_key
        self.identity_attributes = identity_attributes
        self.penalty = penalty
        self.min_auth_methods = min_auth_methods
        self.saml_response_url = saml_response_url
