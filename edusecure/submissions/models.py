from django.conf import settings
from django.db import models


class Assignment(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    deadline = models.DateTimeField()
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='assignments_created',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title


class Submission(models.Model):
    student    = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='submissions',
    )
    assignment = models.ForeignKey(
        Assignment,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='submissions',
    )
    title = models.CharField(max_length=255)
    submitted_at = models.DateTimeField(auto_now_add=True)
    is_late = models.BooleanField(default=False)
    encrypted_content = models.TextField()
    hmac_digest = models.CharField(max_length=64)
    vt_result = models.TextField(blank=True)
    vt_safe = models.BooleanField(null=True)
    signature = models.TextField(blank=True)
    signer_public_key = models.TextField(blank=True)

    class Meta:
        ordering = ['-submitted_at']

    def __str__(self):
        return f"{self.title} — {self.student.username}"
