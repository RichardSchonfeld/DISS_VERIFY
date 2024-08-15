from django.db import models
from django.contrib.auth.models import User, AbstractUser
from django.core.exceptions import ValidationError

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
    public_key = models.CharField(max_length=42, unique=True, blank=True, null=True)
    encrypted_private_key = models.TextField(blank=True, null=True)
    encrypted_key_fragment = models.TextField(blank=True, null=True)
    is_web3_user = models.BooleanField(default=False)  # Flag to distinguish between Django and Web3 users

    USERNAME_FIELD = 'username'  # Use 'username' for Web3 users and 'email' for Django users
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username if self.is_web3_user else self.email

    def clean(self):
        # Ensure email is required for Django users (non-Web3)
        if not self.is_web3_user and not self.email:
            raise ValidationError("Email is required for Django users.")
        # Ensure public key is required for Web3 users
        if self.is_web3_user and not self.public_key:
            raise ValidationError("Public key is required for Web3 users.")

    def save(self, *args, **kwargs):
        if self.is_web3_user:
            self.email = None  # Ensure Web3 users don't have an email
            self.password = ''  # Ensure Web3 users don't have a password
        else:
            if not self.email:
                raise ValueError("Email is required for Django users.")
            self.username = self.email
        super().save(*args, **kwargs)

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
