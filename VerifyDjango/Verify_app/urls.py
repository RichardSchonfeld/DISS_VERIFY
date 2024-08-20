from django.urls import path
from .views import *
from .web3_utils import get_nonce

urlpatterns = [
    path('', index, name='index'),
    path('create-claim/', create_claim, name='create-claim'),
    path('list-claims/', ListClaimsView.as_view(), name='list-claims'),
    path('login/', login_view, name='login_view'),
    path('web3/nonce/', get_nonce, name='get_nonce'),
    path('web3/verify/', verify_signature, name='verify_signature'),
    path('register/', register, name='register'),
    path('recover_key/', recover_key, name='recover_key'),
    path('view-claims/', view_claims, name='view-claims'),
    path('transaction-confirmation/', transaction_confirmation, name='transaction_confirmation'),
    path('decrypt-claim-data/', decrypt_claim, name='decrypt-claim-data'),
    path('sign-certificate/', sign_certificate, name='sign_certificate'),
    path('store-signed-certificate/', store_signed_certificate, name='store_signed_certificate'),
    path('verify-signature/', verify_signature, name="verify_signature"),
]
