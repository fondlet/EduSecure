from django.contrib import messages
from django.shortcuts import redirect, render

from utils.decorators import lecturer_required

from .models import AuditLog


@lecturer_required
def audit_log_view(request):
    logs = AuditLog.objects.select_related('user').all()[:500]
    return render(request, 'audit/log.html', {'logs': logs})
