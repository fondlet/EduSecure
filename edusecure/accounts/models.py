"""
EduSecure user model.

Extends Django's AbstractUser to add:
  role        — student | lecturer | admin
  totp_secret — base-32 TOTP secret provisioned during MFA setup
  mfa_enabled — flag set once the user has scanned the QR and verified a code

The TOTP implementation follows RFC 6238 (same as the manual totp.py
coursework script).  pyotp generates the same values as that script given the
same secret — the manual version exists to show the HMAC-SHA1 maths.
"""

import pyotp
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    ROLE_CHOICES = [
        ('student',  'Student'),
        ('lecturer', 'Lecturer'),
        ('admin',    'Admin'),
    ]

    role        = models.CharField(max_length=20, choices=ROLE_CHOICES, default='student')
    totp_secret = models.CharField(max_length=64, blank=True)   # base-32 encoded
    mfa_enabled = models.BooleanField(default=False)

    def generate_totp_secret(self) -> str:
        """Create a fresh base-32 secret, save it, and return it."""
        self.totp_secret = pyotp.random_base32()
        self.save(update_fields=['totp_secret'])
        return self.totp_secret

    def get_totp_uri(self) -> str:
        """Return the otpauth:// URI that QR-code-based authenticators scan."""
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email or self.username,
            issuer_name="EduSecure",
        )

    def verify_totp(self, token: str) -> bool:
        """
        Verify a 6-digit TOTP token.  Allows a ±1 window (30 s either side)
        to tolerate slight clock drift between server and authenticator app.
        """
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)
