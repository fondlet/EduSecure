from django.conf import settings
from django.db import models


class Grade(models.Model):
    submission = models.OneToOneField(
        'submissions.Submission',
        on_delete=models.CASCADE,
        related_name='grade',
    )
    grader = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='grades_given',
    )
    graded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    encrypted_score = models.TextField()
    encrypted_feedback = models.TextField()
    hmac_digest = models.CharField(max_length=64)

    class Meta:
        ordering = ['-graded_at']

    def __str__(self):
        return f"Grade for {self.submission.title} — {self.submission.student.username}"
