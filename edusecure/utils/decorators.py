from functools import wraps

from django.contrib import messages
from django.shortcuts import redirect


def lecturer_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        if request.user.role not in ('lecturer', 'admin'):
            messages.error(request, "Access denied — this area is for lecturers only.")
            return redirect('submission_list')
        return view_func(request, *args, **kwargs)
    return _wrapped
