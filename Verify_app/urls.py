from django.urls import path
from .views import *
from .web3_utils import get_nonce, verify_signature_login_metamask, verify_signature_login_metamask_authority_creation

from .forms import send_demo, email_status
urlpatterns = [
    path('', index, name='index'),
    path('home', index, name='home'),
    path('create-claim/', create_claim, name='create-claim'),
    path('list-claims/', view_claims, name='view-claims'),
    path('login/', login_view, name='login'),
    path('web3/nonce/', get_nonce, name='get_nonce'),
    path('web3/verify/', verify_signature_login_metamask, name='verify_signature'),
    path('web3/verify_authority/', verify_signature_login_metamask_authority_creation, name='verify_signature'),
    path('register/', register, name='register'),
    path('register_authority/', register_authority, name='register-authority'),
    path('recover_key/', recover_key, name='recover_key'),
    #path('view-claims/', view_claims, name='view-claims'),
    path('transaction-confirmation/', transaction_confirmation, name='transaction_confirmation'),
    path('decrypt-claim-data/', decrypt_claim, name='decrypt-claim-data'),
    path('sign-certificate/', sign_certificate_view, name='sign-certificate'),
    path('logout/', logout_view, name='logout'),
    path('store-signed-certificate/', store_signed_certificate, name='store_signed_certificate'),
    path('verify-signature/', verify_signature, name="verify-signature"),
    path('user-profile/', user_profile_view, name="user-profile"),
    path('authority-profile/', authority_profile_view, name="authority-profile"),
    path('show-private-key/', decrypt_private_key_view, name="show-private-key"),
    path('claim/<int:claim_id>/', claim_detail_view, name='claim-detail'),
    path('tatum-webhook-1/', tatum_webhook_create, name='tatum_webhook'),
    path('tatum-webhook-2/', tatum_webhook_sign, name='tatum_webhook'),
    path('send_demo/', send_demo, name='send_demo'),
    path('email_status/', email_status, name='email_status'),
]
