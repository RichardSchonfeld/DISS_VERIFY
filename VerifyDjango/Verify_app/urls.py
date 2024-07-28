from django.urls import path
from .views import index, ListClaimsView, CreateClaimView

urlpatterns = [
    path('', index, name='index'),
    path('create_claim/', CreateClaimView.as_view(), name='get_claims'),
    path('list-claims/', ListClaimsView.as_view(), name='list-claims'),
]
