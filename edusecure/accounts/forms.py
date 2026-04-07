from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User

FC = {'class': 'form-control'}   # Bootstrap form-control shorthand


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs=FC))
    role  = forms.ChoiceField(choices=User.ROLE_CHOICES,
                              widget=forms.Select(attrs={'class': 'form-select'}))

    class Meta:
        model  = User
        fields = ('username', 'email', 'role', 'password1', 'password2')
        widgets = {'username': forms.TextInput(attrs=FC)}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs.update(FC)
        self.fields['password2'].widget.attrs.update(FC)


class LoginForm(forms.Form):
    username = forms.CharField(max_length=150, widget=forms.TextInput(attrs=FC))
    password = forms.CharField(widget=forms.PasswordInput(attrs=FC))


class MFATokenForm(forms.Form):
    token = forms.CharField(
        max_length=6,
        min_length=6,
        label="6-digit code",
        widget=forms.TextInput(attrs={
            **FC,
            'autocomplete': 'one-time-code',
            'inputmode':    'numeric',
            'placeholder':  '000000',
        }),
    )
