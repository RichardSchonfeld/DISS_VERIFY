from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('Verify_app.urls')),
    path('', include('Verify_app.urls')),
]
