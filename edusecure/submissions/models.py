"""
Submission model.

Each submission stores:
  • encrypted_content — AES-256-GCM ciphertext of the file text / message
  • hmac_digest       — HMAC-SHA256 over the raw file bytes; used to detect tampering
  • vt_result         — VirusTotal scan verdict stored as JSON string
  • vt_safe           — nullable bool; None = not yet scanned / timed out

This directly addresses the assignment incident: "An attacker modified a
submitted assignment file" — the HMAC will fail on any post-upload modification.
"""

from django.conf import settings
from django.db import models


class Submission(models.Model):
    student           = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                          related_name='submissions')
    title             = models.CharField(max_length=255)
    submitted_at      = models.DateTimeField(auto_now_add=True)

    # AES-256-GCM ciphertext (JSON blob: nonce + ciphertext + tag)
    encrypted_content = models.TextField()

    # HMAC-SHA256 of the original file bytes — integrity check
    hmac_digest       = models.CharField(max_length=64)

    # VirusTotal results
    vt_result         = models.TextField(blank=True)   # human-readable message
    vt_safe           = models.BooleanField(null=True) # None = unknown

    class Meta:
        ordering = ['-submitted_at']

    def __str__(self):
        return f"{self.title} — {self.student.username}"
