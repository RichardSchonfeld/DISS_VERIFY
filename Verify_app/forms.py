import os

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.conf import settings
from .encryption_utils import encrypt_shamir_key
from .models import CustomUser, KeyFragment, Claim

from PyPDF2 import PdfWriter, PdfReader


class UserRegisterForm(UserCreationForm):
    email = forms.EmailField()

    class Meta:
        model = CustomUser
        fields = ['email', 'password1', 'password2']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError('Email already registered')
        return email


### Database Operations
def store_key_fragment(user, fragmnet_data, ipfs_hash):
    KeyFragment.objects.create(user=user, fragment=fragmnet_data, ipfs_hash=ipfs_hash)


def get_user_by_address(address):
    return CustomUser.objects.get(address=address)


def get_authority_name_from_address(address):
    try:
        authority = CustomUser.objects.get(address=address)
        return authority.institution_name if authority.institution_name else address
    except CustomUser.DoesNotExist:
        return address


def store_and_distribute_key_fragments(shares, user_profile, authority_address, IPFS_hash):
    claimant_share = shares[0]
    server_share = shares[1]
    authority_share = shares[2]

    try:
        # Symmetric Encryption
        claimant_share = encrypt_shamir_key(claimant_share)
        server_share = encrypt_shamir_key(server_share)
        authority_share = encrypt_shamir_key(authority_share)

        # Storing
        store_key_fragment(user_profile, claimant_share, IPFS_hash)

        server_user = get_user_by_address(settings.SERVER_OP_ACC_ADDRESS)
        store_key_fragment(server_user, server_share, IPFS_hash)

        authority_user = get_user_by_address(authority_address)
        store_key_fragment(authority_user, authority_share, IPFS_hash)
    except Exception as e:

        raise Exception(f'Failed to distribute Shamir keys: {str(e)}')


import json
def save_claim_to_django_DB(request, transaction_hash, claim_id):
    try:
        data = json.loads(request.body.decode('utf-8')).get('claimData')

        # Get the authority user based on the provided address
        authority_address = data.get('authority')
        authority_user = CustomUser.objects.get(address=authority_address)
        ipfs_hash = data.get('ipfs_hash')

        # Save the claim to the database
        Claim.objects.create(
            claim_id=claim_id,  # Use the extracted claim_id
            requester=request.user,
            authority=authority_user,
            ipfs_hash=ipfs_hash,
            transaction_hash=transaction_hash,
            signed=False
        )

    except CustomUser.DoesNotExist:
        # Handle case where authority user doesn't exist
        raise Exception(f'Authority with address {authority_address} not found.')

    except Exception as e:
        raise Exception(f'Failed to save claim: {str(e)}')


def embed_metadata(certificate_pdf_bytes, claim_id, authority_address):
    """
    Embed claim ID and authority address into the PDF certificate as metadata.
    """
    pdf_reader = PdfReader(BytesIO(certificate_pdf_bytes))
    pdf_writer = PdfWriter()

    # Add metadata
    metadata = {
        '/ClaimID': str(claim_id),
        '/AuthorityAddress': authority_address
    }

    # Copy pages from the original PDF
    for page_num in range(len(pdf_reader.pages)):  # Use len(reader.pages)
        pdf_writer.add_page(pdf_reader.pages[page_num])  # Use reader.pages[page_num] instead of getPage()

    pdf_writer.add_metadata(metadata)

    # Write the new PDF with metadata
    output_stream = BytesIO()
    pdf_writer.write(output_stream)

    return output_stream.getvalue()


import re
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.shortcuts import render
from django.urls import reverse
from django.http import HttpResponseRedirect
def is_ucl_email(email):
    return re.match(r"^[a-zA-Z0-9_.+-]+@ucl.ac.uk$", email)

def send_demo(request):
    if request.method == 'POST':
        ucl_email = request.POST.get('ucl_email')

        if is_ucl_email(ucl_email):
            try:
                # Path to the file located in the ROOT_DIR
                file_path = os.path.join(settings.BASE_DIR, 'Demo_notes_verify_platform.pdf')
                user = os.getenv('DEMO_USER_UNAME')
                userpass = os.getenv('DEMO_USER_PSSWD')
                usersk = os.getenv('DEMO_USER_PRIVATE_KEY')

                email_content = f"""
                Hello,
                
                Please find a demo PDF file attached. A video is also available here: https://youtu.be/UzSZDjNFzMo
                
                To interact, two accounts are provided for you - 
                    Standard username / password (Claimant) : {user} / {userpass}
                    Metamask user for import (Authority) : {usersk}
                
                """

                # Create and send the email
                email = EmailMessage(
                    'UCL Thesis Demo Document',
                    email_content,
                    settings.DEFAULT_FROM_EMAIL,
                    [ucl_email],
                )
                email.attach_file(file_path)
                email.send(fail_silently=False)

                # Redirect to the 'email_status' page with a success message
                return HttpResponseRedirect(reverse('email_status') + '?status=success')
            except Exception as e:
                # Redirect with an error message
                return HttpResponseRedirect(reverse('email_status') + '?status=error&message=Failed to send email.')
        else:
            return HttpResponseRedirect(reverse('email_status') + '?status=error&message=Invalid UCL email.')
    else:
        return HttpResponseRedirect(reverse('email_status') + '?status=error&message=Invalid request method.')

def email_status(request):
    status = request.GET.get('status', None)
    message = request.GET.get('message', '')

    if status == 'success':
        message = "The demo document has been sent to your email."

    return render(request, 'email_status.html', {
        'status': status,
        'message': message
    })



from io import BytesIO
from django.http import FileResponse

"""def generate_pdf_certificate(certificate_data):
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)

    pdf.drawString(100, 800, "University Name Certificate of Graduation")
    pdf.drawString(100, 750, f"Name: {certificate_data['name']}")
    pdf.drawString(100, 720, f"Student Number: {certificate_data['student_number']}")
    pdf.drawString(100, 690, f"Year of Graduation: {certificate_data['year_of_graduation']}")
    pdf.drawString(100, 660, f"Course: {certificate_data['course_details']}")
    pdf.drawString(100, 630, f"Issued on: {certificate_data['date_of_issue']}")
    pdf.drawString(100, 600, f"Issued by: {certificate_data['issuer']}")

    pdf.showPage()
    pdf.save()

    buffer.seek(0)
    return buffer


def download_pdf_certificate(request, certificate_data):
    buffer = generate_pdf_certificate(certificate_data)
    return FileResponse(buffer, as_attachment=True, filename=f"{certificate_data['name']}_certificate.pdf")"""