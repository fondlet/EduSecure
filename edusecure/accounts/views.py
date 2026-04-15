import io
import base64

import qrcode
from django.contrib import auth, messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from audit.models import log_event
from .forms import LoginForm, MFATokenForm, RegisterForm
from .models import User


def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Account created — please log in.")
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'accounts/register.html', {'form': form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('submission_list')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            user = auth.authenticate(
                request,
                username=form.cleaned_data['username'],
                password=form.cleaned_data['password'],
            )
            if user is None:
                log_event(None, 'login_failed',
                          f"Failed login for username '{form.cleaned_data['username']}'", request)
                messages.error(request, "Invalid username or password.")
            elif user.mfa_enabled:
                request.session['mfa_pending_user_id'] = user.pk
                return redirect('mfa_verify')
            else:
                auth.login(request, user)
                log_event(user, 'login', f"Login (no MFA) — {user.username}", request)
                messages.info(request, "MFA not yet set up — please configure it now.")
                return redirect('mfa_setup')
    else:
        form = LoginForm()

    return render(request, 'accounts/login.html', {'form': form})


def mfa_verify_view(request):
    user_id = request.session.get('mfa_pending_user_id')
    if not user_id:
        return redirect('login')

    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return redirect('login')

    if request.method == 'POST':
        form = MFATokenForm(request.POST)
        if form.is_valid():
            if user.verify_totp(form.cleaned_data['token']):
                del request.session['mfa_pending_user_id']
                # need to set backend manually when not going through authenticate()
                user.backend = 'django.contrib.auth.backends.ModelBackend'
                auth.login(request, user)
                log_event(user, 'login', f"Login (MFA verified) — {user.username}", request)
                return redirect('submission_list')
            else:
                messages.error(request, "Invalid or expired code — try again.")
    else:
        form = MFATokenForm()

    return render(request, 'accounts/mfa_verify.html', {'form': form})


@login_required
def mfa_setup_view(request):
    user = request.user

    if request.method == 'POST':
        form = MFATokenForm(request.POST)
        if form.is_valid():
            if user.totp_secret and user.verify_totp(form.cleaned_data['token']):
                user.mfa_enabled = True
                user.save(update_fields=['mfa_enabled'])
                messages.success(request, "MFA enabled successfully.")
                return redirect('submission_list')
            else:
                messages.error(request, "Code did not match — please try again.")
        secret = user.totp_secret
    else:
        if not user.totp_secret or request.GET.get('reset'):
            secret = user.generate_totp_secret()
            user.mfa_enabled = False
            user.save(update_fields=['mfa_enabled'])
        else:
            secret = user.totp_secret
        form = MFATokenForm()

    uri = user.get_totp_uri()
    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render(request, 'accounts/mfa_setup.html', {
        'form': form,
        'qr_b64': qr_b64,
        'secret': secret,
    })


@login_required
def logout_view(request):
    log_event(request.user, 'logout', f"Logout — {request.user.username}", request)
    auth.logout(request)
    return redirect('login')
