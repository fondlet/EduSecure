import pyotp
from django.contrib.auth.models import AbstractUser
from django.db import models
from utils.crypto import generate_rsa_keypair


class User(AbstractUser):
    ROLE_CHOICES = [
        ('student', 'Student'),
        ('lecturer', 'Lecturer'),
        ('admin', 'Admin'),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='student')
    totp_secret = models.CharField(max_length=64, blank=True)
    mfa_enabled = models.BooleanField(default=False)

    rsa_private_key = models.TextField(blank=True)
    rsa_public_key = models.TextField(blank=True)

    def generate_totp_secret(self):
        self.totp_secret = pyotp.random_base32()
        self.save(update_fields=['totp_secret'])
        return self.totp_secret

    def get_totp_uri(self):
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email or self.username,
            issuer_name="EduSecure",
        )

    def ensure_rsa_keypair(self):
        if not self.rsa_private_key:
            private_pem, public_pem = generate_rsa_keypair()
            self.rsa_private_key = private_pem
            self.rsa_public_key = public_pem
            self.save(update_fields=['rsa_private_key', 'rsa_public_key'])

    def verify_totp(self, token):
        totp = pyotp.TOTP(self.totp_secret)
        # window=4 gives ~2 min leeway for clock drift
        return totp.verify(token, valid_window=4)
