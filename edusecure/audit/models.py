from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('login', 'Login'),
        ('login_failed', 'Login Failed'),
        ('logout', 'Logout'),
        ('submission_create', 'Submission Created'),
        ('grade_create', 'Grade Created'),
        ('grade_update', 'Grade Updated'),
        ('material_upload', 'Material Uploaded'),
        ('assignment_create', 'Assignment Created'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='audit_logs',
    )
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    detail = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        name = self.user.username if self.user else 'anonymous'
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} | {name} | {self.action}"


def log_event(user, action, detail='', request=None):
    ip = None
    if request:
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        ip = forwarded.split(',')[0].strip() if forwarded else request.META.get('REMOTE_ADDR')
    # user can be None for failed logins
    actual_user = user if (user and hasattr(user, 'pk') and user.pk) else None
    AuditLog.objects.create(
        user=actual_user,
        action=action,
        detail=detail,
        ip_address=ip,
    )
