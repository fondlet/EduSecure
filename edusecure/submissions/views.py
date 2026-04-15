from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from audit.models import log_event
from utils.crypto import compute_hmac, decrypt_aes_gcm, encrypt_aes_gcm, sign_data, verify_signature
from utils.decorators import lecturer_required
from utils.virustotal import scan_file

from .models import Assignment, Submission


class SubmissionForm(forms.Form):
    title = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
    )
    assignment = forms.ModelChoiceField(
        queryset=Assignment.objects.all(),
        required=False,
        empty_label="No assignment (standalone upload)",
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    file = forms.FileField(
        help_text="Upload your assignment file (text/PDF).",
        widget=forms.FileInput(attrs={'class': 'form-control'}),
    )

class AssignmentForm(forms.Form):
    title = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
    )
    description = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
    )
    deadline = forms.DateTimeField(
        widget=forms.DateTimeInput(
            attrs={'class': 'form-control', 'type': 'datetime-local'},
            format='%Y-%m-%dT%H:%M',
        ),
        input_formats=['%Y-%m-%dT%H:%M'],
    )


@login_required
def upload_submission(request):
    if request.method == 'POST':
        form = SubmissionForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded = request.FILES['file']
            raw_bytes = uploaded.read()
            key = settings.ENCRYPTION_KEY
            assignment = form.cleaned_data.get('assignment')

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
                return render(request, 'submissions/upload.html', {'form': form})

            request.user.ensure_rsa_keypair()
            # sign the hmac rather than raw bytes to keep the signature small
            signature = sign_data(hmac_digest.encode(), request.user.rsa_private_key)

            is_late = False
            if assignment:
                deadline = assignment.deadline
                if timezone.is_naive(deadline):
                    deadline = timezone.make_aware(deadline)
                is_late = timezone.now() > deadline

            sub = Submission.objects.create(
                student=request.user,
                assignment=assignment,
                title=form.cleaned_data['title'],
                encrypted_content=encrypted,
                hmac_digest=hmac_digest,
                vt_result=vt['message'],
                vt_safe=vt['safe'],
                signature=signature,
                signer_public_key=request.user.rsa_public_key,
                is_late=is_late,
            )

            detail = f"Submission '{sub.title}' (ID {sub.pk})"
            if assignment:
                detail += f" for assignment '{assignment.title}'"
            if is_late:
                detail += " [LATE]"
            log_event(request.user, 'submission_create', detail, request)

            if is_late:
                messages.warning(request,
                    "Your submission was accepted but is marked late (past the deadline).")
            return redirect('submission_list')
    else:
        form = SubmissionForm()

    return render(request, 'submissions/upload.html', {'form': form})


@login_required
def list_submissions(request):
    submissions = Submission.objects.filter(student=request.user).select_related('assignment')
    key = settings.ENCRYPTION_KEY

    enriched = []
    for sub in submissions:
        try:
            plaintext = decrypt_aes_gcm(sub.encrypted_content, key)
            decrypted_ok = True
        except Exception:
            plaintext = "[decryption failed — possible tampering]"
            decrypted_ok = False

        sig_ok = False
        if sub.signature and sub.signer_public_key:
            sig_ok = verify_signature(
                sub.hmac_digest.encode(),
                sub.signature,
                sub.signer_public_key,
            )

        enriched.append({
            'sub': sub,
            'plaintext': plaintext[:500],
            'decrypted_ok': decrypted_ok,
            'hmac_ok': decrypted_ok,  # if decryption passed, GCM auth tag covers integrity too
            'sig_ok': sig_ok,
        })

    return render(request, 'submissions/list.html', {'submissions': enriched})


@lecturer_required
def list_assignments(request):
    assignments = Assignment.objects.select_related('created_by').all()
    return render(request, 'submissions/assignments.html', {
        'assignments': assignments,
        'now': timezone.now(),
    })


@lecturer_required
def create_assignment(request):
    if request.method == 'POST':
        form = AssignmentForm(request.POST)
        if form.is_valid():
            deadline = form.cleaned_data['deadline']
            if timezone.is_naive(deadline):
                deadline = timezone.make_aware(deadline)
            a = Assignment.objects.create(
                title=form.cleaned_data['title'],
                description=form.cleaned_data.get('description', ''),
                deadline=deadline,
                created_by=request.user,
            )
            log_event(request.user, 'assignment_create',
                      f"Assignment '{a.title}' (ID {a.pk}), "
                      f"deadline {a.deadline:%Y-%m-%d %H:%M}", request)
            messages.success(request, f"Assignment '{a.title}' created.")
            return redirect('list_assignments')
    else:
        form = AssignmentForm()
    return render(request, 'submissions/create_assignment.html', {'form': form})


@lecturer_required
def late_report(request):
    late_subs = (
        Submission.objects
        .filter(is_late=True)
        .select_related('student', 'assignment')
        .order_by('assignment__title', 'submitted_at')
    )
    return render(request, 'submissions/late_report.html', {'late_subs': late_subs})
