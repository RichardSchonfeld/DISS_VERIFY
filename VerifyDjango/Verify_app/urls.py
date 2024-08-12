from django.urls import path
from .views import index, ListClaimsView, CreateClaimView, upload_ipfs_view, login_view
from .web3_utils import get_nonce, verify_signature

urlpatterns = [
    path('', index, name='index'),
    path('create-claim/', CreateClaimView.as_view(), name='get_claims'),
    path('list-claims/', ListClaimsView.as_view(), name='list-claims'),
    path('upload-ipfs/', upload_ipfs_view, name='upload-ipfs'),
    path('login/', login_view, name='login_view'),
    path('web3/nonce/', get_nonce, name='get_nonce'),
    path('web3/verify/', verify_signature, name='verify_signature'),

]
