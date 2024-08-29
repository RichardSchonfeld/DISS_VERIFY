from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import CustomUser, KeyFragment

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
