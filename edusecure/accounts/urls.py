from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/',    views.login_view,    name='login'),
    path('logout/',   views.logout_view,   name='logout'),
    path('mfa/setup/',  views.mfa_setup_view,  name='mfa_setup'),
    path('mfa/verify/', views.mfa_verify_view, name='mfa_verify'),
]
