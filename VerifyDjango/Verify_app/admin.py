from django.contrib import admin
from .models import CustomUser, KeyFragment

admin.site.register(CustomUser)
admin.site.register(KeyFragment)