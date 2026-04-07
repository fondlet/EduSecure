"""
Accounts views — register, login (with optional TOTP MFA), MFA setup, logout.

Two-step login flow:
  1. User submits username + password  → credentials verified
  2a. If MFA enabled  → store pending user ID in session, redirect to mfa_verify
  2b. If MFA disabled → log in immediately, redirect to mfa_setup prompt
"""

import io
import base64

import qrcode
from django.contrib import auth, messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from .forms import LoginForm, MFATokenForm, RegisterForm
from .models import User


# ── Registration ──────────────────────────────────────────────────────────────

def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, "Account created — please log in.")
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'accounts/register.html', {'form': form})


# ── Login (step 1 — password) ─────────────────────────────────────────────────

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
                messages.error(request, "Invalid username or password.")
            elif user.mfa_enabled:
                # Park the user ID in the session; finish login after TOTP check
                request.session['mfa_pending_user_id'] = user.pk
                return redirect('mfa_verify')
            else:
                auth.login(request, user)
                messages.info(request, "MFA not yet set up — please configure it now.")
                return redirect('mfa_setup')
    else:
        form = LoginForm()

    return render(request, 'accounts/login.html', {'form': form})


# ── Login (step 2 — TOTP verify) ──────────────────────────────────────────────

def mfa_verify_view(request):
    """Verify the 6-digit TOTP from Microsoft Authenticator."""
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
                # Full login — clear the pending flag
                del request.session['mfa_pending_user_id']
                # backend must be set explicitly when logging in a user fetched
                # directly from the DB rather than via auth.authenticate()
                user.backend = 'django.contrib.auth.backends.ModelBackend'
                auth.login(request, user)
                return redirect('submission_list')
            else:
                messages.error(request, "Invalid or expired code — try again.")
    else:
        form = MFATokenForm()

    return render(request, 'accounts/mfa_verify.html', {'form': form})


# ── MFA setup — generate QR code for Microsoft Authenticator ─────────────────

@login_required
def mfa_setup_view(request):
    """
    Generate a fresh TOTP secret, render it as a QR code, and let the user
    confirm with their first token before enabling MFA.

    Microsoft Authenticator (and Google Authenticator) both implement RFC 6238
    TOTP — the same algorithm demonstrated manually in the totp.py script.
    Scanning this QR registers EduSecure as an account in the app.
    """
    user = request.user

    if request.method == 'POST':
        form = MFATokenForm(request.POST)
        if form.is_valid():
            # Only enable MFA if a valid token is provided — proves the QR was scanned
            if user.totp_secret and user.verify_totp(form.cleaned_data['token']):
                user.mfa_enabled = True
                user.save(update_fields=['mfa_enabled'])
                messages.success(request, "MFA enabled successfully.")
                return redirect('submission_list')
            else:
                messages.error(request, "Code did not match — please scan the QR again.")

    # Generate (or regenerate) the secret and build the QR code
    secret = user.generate_totp_secret()
    uri    = user.get_totp_uri()

    qr_img = qrcode.make(uri)
    buf    = io.BytesIO()
    qr_img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render(request, 'accounts/mfa_setup.html', {
        'form':   MFATokenForm(),
        'qr_b64': qr_b64,
        'secret': secret,          # shown as fallback manual-entry key
    })


# ── Logout ────────────────────────────────────────────────────────────────────

@login_required
def logout_view(request):
    auth.logout(request)
    return redirect('login')
