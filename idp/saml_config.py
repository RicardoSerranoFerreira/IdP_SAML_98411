from flask_saml2.sp import ServiceProvider
from flask_saml2.utils import certificate_from_file, private_key_from_file
from models import RegisteredService

# Store registered services
registered_services = {}


class MyServiceProvider(ServiceProvider):
    def get_sp_entity_id(self):
        return 'http://localhost:5000/saml'

    def get_sp_private_key(self):
        return private_key_from_file('../certificados/private_key.pem')

    def get_sp_certificate(self):
        return certificate_from_file('../certificados/public_certificate.pem')

    def get_idp_metadata_url(self):
        return 'http://localhost:5000/saml/metadata'

    def determine_mfa_methods(self, service_id, user_id):
        service = registered_services.get(service_id)
        risk_score = service.penalty
        mfa_count = min(1 + risk_score // 10, 4)
        return mfa_count

    def login_successful(self, user_id):
        print(f"User {user_id} successfully authenticated")
