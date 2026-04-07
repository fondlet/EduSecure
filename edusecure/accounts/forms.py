from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)
    role  = forms.ChoiceField(choices=User.ROLE_CHOICES)

    class Meta:
        model  = User
        fields = ('username', 'email', 'role', 'password1', 'password2')


class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)


class MFATokenForm(forms.Form):
    token = forms.CharField(
        max_length=6,
        min_length=6,
        label="6-digit code",
        widget=forms.TextInput(attrs={'autocomplete': 'one-time-code', 'inputmode': 'numeric'}),
    )
