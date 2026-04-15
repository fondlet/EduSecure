from django.conf import settings
from django.db import models


class LearningMaterial(models.Model):
    uploader          = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                          related_name='materials_uploaded')
    title             = models.CharField(max_length=255)
    description       = models.CharField(max_length=500, blank=True)
    uploaded_at       = models.DateTimeField(auto_now_add=True)
    encrypted_content = models.TextField()
    hmac_digest       = models.CharField(max_length=64)
    vt_result         = models.TextField(blank=True)
    vt_safe           = models.BooleanField(null=True)
    signature         = models.TextField(blank=True)
    signer_public_key = models.TextField(blank=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.title} — {self.uploader.username}"
