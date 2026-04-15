from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.shortcuts import redirect, render

from utils.crypto import compute_hmac, decrypt_aes_gcm, encrypt_aes_gcm, sign_data, verify_signature
from utils.virustotal import scan_file

from .models import LearningMaterial


class MaterialForm(forms.Form):
    title       = forms.CharField(max_length=255)
    description = forms.CharField(max_length=500, required=False,
                                  widget=forms.Textarea(attrs={'rows': 2}))
    file        = forms.FileField(help_text="Upload a lecture note or resource file.")


def _lecturer_required(request):
    return request.user.role in ('lecturer', 'admin')


@login_required
def upload_material(request):
    if not _lecturer_required(request):
        messages.error(request, "Only lecturers and admins can upload learning materials.")
        return redirect('material_list')

    if request.method == 'POST':
        form = MaterialForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded  = request.FILES['file']
            raw_bytes = uploaded.read()
            key       = settings.ENCRYPTION_KEY

            hmac_digest = compute_hmac(raw_bytes, key)

            try:
                text_content = raw_bytes.decode('utf-8', errors='replace')
            except Exception:
                text_content = raw_bytes.hex()
            encrypted = encrypt_aes_gcm(text_content, key)

            uploaded.seek(0)
            vt = scan_file(uploaded, uploaded.name)

            if vt['safe'] is False:
                messages.error(request,
                    f"Upload blocked — VirusTotal flagged this file as malicious: {vt['message']}")
                return render(request, 'materials/upload.html', {'form': form})

            request.user.ensure_rsa_keypair()
            signature = sign_data(hmac_digest.encode(), request.user.rsa_private_key)

            LearningMaterial.objects.create(
                uploader          = request.user,
                title             = form.cleaned_data['title'],
                description       = form.cleaned_data['description'],
                encrypted_content = encrypted,
                hmac_digest       = hmac_digest,
                vt_result         = vt['message'],
                vt_safe           = vt['safe'],
                signature         = signature,
                signer_public_key = request.user.rsa_public_key,
            )
            messages.success(request, "Learning material uploaded successfully.")
            return redirect('material_list')
    else:
        form = MaterialForm()

    return render(request, 'materials/upload.html', {'form': form})


@login_required
def list_materials(request):
    materials = LearningMaterial.objects.all()
    key       = settings.ENCRYPTION_KEY

    enriched = []
    for mat in materials:
        try:
            plaintext    = decrypt_aes_gcm(mat.encrypted_content, key)
            decrypted_ok = True
        except Exception:
            plaintext    = "[decryption failed — possible tampering]"
            decrypted_ok = False

        sig_ok = False
        if mat.signature and mat.signer_public_key:
            sig_ok = verify_signature(
                mat.hmac_digest.encode(),
                mat.signature,
                mat.signer_public_key,
            )

        enriched.append({
            'mat':          mat,
            'plaintext':    plaintext[:500],
            'decrypted_ok': decrypted_ok,
            'sig_ok':       sig_ok,
        })

    return render(request, 'materials/list.html', {
        'materials':         enriched,
        'can_upload':        _lecturer_required(request),
    })
