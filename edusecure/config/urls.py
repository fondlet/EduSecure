from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

urlpatterns = [
    path('admin/',       admin.site.urls),
    path('accounts/',    include('accounts.urls')),
    path('submissions/', include('submissions.urls')),
    path('grades/',      include('grades.urls')),
    path('',             lambda req: redirect('login'), name='home'),
]
