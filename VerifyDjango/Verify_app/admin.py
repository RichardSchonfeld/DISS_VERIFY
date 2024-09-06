from django.contrib import admin
from .models import CustomUser, KeyFragment, Certificate, Claim

admin.site.register(CustomUser)
admin.site.register(KeyFragment)
admin.site.register(Certificate)
admin.site.register(Claim)