from django.contrib import admin
from .models import CustomUser, KeyFragment, Certificate

admin.site.register(CustomUser)
admin.site.register(KeyFragment)
admin.site.register(Certificate)