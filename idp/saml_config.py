from saml2 import config as saml_config

def get_saml_config():
    return saml_config.SPConfig(
        entityid='http://localhost:5000/saml/metadata',
        service={
            'sp': {
                'name': 'Serviço 1',
                'endpoints': {
                    'assertion_consumer_service': [
                        ('http://localhost:5000/saml/acs', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                    ],
                    'single_logout_service': [
                        ('http://localhost:5000/saml/sls', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                    ],
                },
                'x509cert': open('certs/sp_cert.pem').read(),
                'privatekey': open('certs/sp_key.pem').read(),
            },
            'idp': {
                'name': 'IdP Home',
                'endpoints': {
                    'single_sign_on_service': [
                        ('http://localhost:5000/saml/sso', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                    ],
                    'single_logout_service': [
                        ('http://localhost:5000/saml/slo', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                    ],
                },
                'x509cert': open('certs/idp_cert.pem').read(),
            },
        }
    )

def generate_saml_response(user, service):
    try:
        saml_config = get_saml_config()
        saml_server = saml_server.Server(config=saml_config)
        authn_request = AuthnRequest(
            issuer='http://localhost:5000/saml/metadata',
            name_id=NameID(
                format='urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
                text=user.username
            )
        )
        response = saml_server.create_authn_response(
            authn_request=authn_request,
            destination=service.saml_response_url,
            name_id=user.username
        )
        signed_response = response.to_string()
        return signed_response
    except SAMLError as e:
        logging.error(f'SAML Error: {e}')
        return 'Error generating SAML response', 500