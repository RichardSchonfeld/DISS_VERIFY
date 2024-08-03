from django.urls import path
from .views import index, ListClaimsView, CreateClaimView, upload_ipfs_view

urlpatterns = [
    path('', index, name='index'),
    path('create-claim/', CreateClaimView.as_view(), name='get_claims'),
    path('list-claims/', ListClaimsView.as_view(), name='list-claims'),
    path('upload-ipfs/', upload_ipfs_view, name='upload-ipfs')

]
