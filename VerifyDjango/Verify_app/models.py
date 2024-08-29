from django.db import models
from django.contrib.auth.models import User, AbstractUser
from django.core.exceptions import ValidationError
from django.conf import settings

#class CustomUser(AbstractUser):
#    eth_address = models.CharField(max_length=42, unique=True, blank=True, null=True)
#    encrypted_private_key = models.TextField(blank=True, null=True)

"""class CustomUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    address = models.CharField(max_length=42, unique=True, blank=True, null=True)
    encrypted_private_key = models.TextField(blank=True, null=True)
    email = models.EmailField(blank=False, null=False)
    username = models.TextField(blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email"""


"""class CustomUserDjango(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    #username = models.CharField(max_length=42, unique=True, blank=True, null=True)
    email = models.EmailField(null=False, unique=True)

    public_key = models.CharField(max_length=42, unique=True, blank=True, null=True)
    encrypted_private_key = models.TextField(blank=True, null=True)
    encrypted_key_fragment = models.TextField(blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email


class Web3Account(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    public_key = models.CharField(max_length=42, unique=True, blank=False, null=False)

    USERNAME_FIELD = 'public_key'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.public_key"""


class CustomUser(AbstractUser):
    email = models.EmailField(null=True, unique=True, blank=True)
    address = models.CharField(max_length=42, unique=True, blank=True, null=True)
    encrypted_private_key = models.TextField(blank=True, null=True)
    is_web3_user = models.BooleanField(default=False)  # Flag to distinguish between Django and Web3 users
    is_authority = models.BooleanField(default=False)
    institution_name = models.CharField(max_length=250, unique=True, blank=True, null=True)

    USERNAME_FIELD = 'username'  # Use 'username' for Web3 users and 'email' for Django users
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username if self.is_web3_user else self.email

    def clean(self):
        # Ensure email is required for Django users (non-Web3)
        if not self.is_web3_user and not self.email:
            raise ValidationError("Email is required for Django users.")
        # Ensure public key is required for Web3 users
        if self.is_web3_user and not self.address:
            raise ValidationError("Public key is required for Web3 users.")
        if self.is_authority and not self.institution_name:
            raise ValidationError("Institution name is required for Authority.")

    def save(self, *args, **kwargs):
        if self.is_web3_user:
            self.email = None  # Ensure Web3 users don't have an email
            self.password = ''  # Ensure Web3 users don't have a password
        else:
            if not self.email:
                raise ValueError("Email is required for Django users.")
            self.username = self.email

        if self.is_authority:
            if not self.institution_name:
                raise ValueError("Institution name is required for Authority.")
            self.username = self.institution_name
        super().save(*args, **kwargs)


class KeyFragment(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='key_fragment')
    ipfs_hash = models.CharField(max_length=255, blank=False, null=False)
    fragment = models.TextField(max_length=255, blank=False, null=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Fragment for {self.user.username}"


class Claim(models.Model):
    requester = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    authority = models.CharField(max_length=255)
    year_of_graduation = models.CharField(max_length=4)
    student_number = models.CharField(max_length=20)
    full_name = models.CharField(max_length=255)
    signed = models.BooleanField(default=False)
    ipfs_hash = models.CharField(max_length=255)
    transaction_hash = models.CharField(max_length=66)

    def __str__(self):
        return f'Claim {self.id} by {self.requester}'

from django.db import models

class Certificate(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)  # Assuming you have a CustomUser model
    certificate_data = models.JSONField()  # Store the certificate data as a JSON object
    certificate_hash = models.CharField(max_length=64)  # SHA-256 hash is 64 characters long
    signature = models.TextField()  # Store the signature as text
    created_at = models.DateTimeField(auto_now_add=True)  # Automatically set the time when created

    def __str__(self):
        return f"Certificate for {self.user.email or self.user.address}"
