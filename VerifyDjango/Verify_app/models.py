from django.db import models
from django.contrib.auth.models import User

class Web3Account(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    address = models.CharField(max_length=42, unique=True)

    def __str__(self):
        return self.address

class Claim(models.Model):
    requester = models.ForeignKey(User, on_delete=models.CASCADE)
    authority = models.CharField(max_length=255)
    year_of_graduation = models.CharField(max_length=4)
    student_number = models.CharField(max_length=20)
    full_name = models.CharField(max_length=255)
    signed = models.BooleanField(default=False)
    ipfs_hash = models.CharField(max_length=255)
    transaction_hash = models.CharField(max_length=66)

    def __str__(self):
        return f'Claim {self.id} by {self.requester}'
