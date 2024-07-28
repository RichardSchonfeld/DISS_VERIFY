from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import render
from django.contrib.auth.models import User
from .models import Claim
from .serializers import ClaimSerializer
from .eth_utils import create_claim, sign_claim, get_claim


def index(request):
    return render(request, "index.html")
class CreateClaimView(APIView):
    def post(self, request):
        data = request.data
        authority = data.get('authority')
        year_of_graduation = data.get('year_of_graduation')
        student_number = data.get('student_number')
        full_name = data.get('full_name')

        tx_hash = create_claim(authority, year_of_graduation, student_number, full_name)

        claim = Claim(
            authority=authority,
            year_of_graduation=year_of_graduation,
            student_number=student_number,
            full_name=full_name,
            ipfs_hash='',  # Assuming IPFS hash is generated separately
            transaction_hash=tx_hash
        )
        claim.save()

        return Response({"tx_hash": tx_hash}, status=status.HTTP_201_CREATED)

class SignClaimView(APIView):
    def post(self, request):
        data = request.data
        claim_id = data.get('claim_id')
        authority_address = data.get('authority_address')

        tx_hash = sign_claim(claim_id, authority_address)

        claim = Claim.objects.get(id=claim_id)
        claim.signed = True
        claim.transaction_hash = tx_hash
        claim.save()

        return Response({"tx_hash": tx_hash}, status=status.HTTP_200_OK)


class ListClaimsView(APIView):
    def get(self, request):
        claim = get_claim(2)
        return Response(claim)

    #queryset = Claim.objects.all()
    #serializer_class = ClaimSerializer