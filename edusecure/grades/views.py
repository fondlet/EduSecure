from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.shortcuts import get_object_or_404, redirect, render

from audit.models import log_event
from utils.crypto import compute_hmac, decrypt_aes_gcm, encrypt_aes_gcm, verify_hmac
from utils.decorators import lecturer_required
from submissions.models import Submission
from .models import Grade


class GradeForm(forms.Form):
    score = forms.IntegerField(
        min_value=0, max_value=100,
        label="Score (0–100)",
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
    )
    feedback = forms.CharField(
        label="Feedback",
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
    )


@lecturer_required
def all_submissions(request):
    submissions = Submission.objects.select_related('student', 'grade', 'assignment').all()
    return render(request, 'grades/all_submissions.html', {'submissions': submissions})

@lecturer_required
def grade_submission(request, submission_id):
    submission = get_object_or_404(Submission, pk=submission_id)

    if hasattr(submission, 'grade'):
        return redirect('edit_grade', submission_id=submission_id)

    if request.method == 'POST':
        form = GradeForm(request.POST)
        if form.is_valid():
            score = str(form.cleaned_data['score'])
            feedback = form.cleaned_data['feedback']
            key = settings.ENCRYPTION_KEY

            raw = f"{score}|{feedback}"
            hmac_digest = compute_hmac(raw.encode(), key)
            enc_score = encrypt_aes_gcm(score, key)
            enc_feedback = encrypt_aes_gcm(feedback, key)

            Grade.objects.create(
                submission=submission,
                grader=request.user,
                encrypted_score=enc_score,
                encrypted_feedback=enc_feedback,
                hmac_digest=hmac_digest,
            )
            log_event(request.user, 'grade_create',
                      f"Graded submission '{submission.title}' (ID {submission.pk}), "
                      f"student '{submission.student.username}', score {score}", request)
            messages.success(request, "Grade saved.")
            return redirect('all_submissions')
    else:
        form = GradeForm()

    return render(request, 'grades/grade_form.html', {
        'form': form,
        'submission': submission,
        'action': 'Grade',
    })


@lecturer_required
def edit_grade(request, submission_id):
    submission = get_object_or_404(Submission, pk=submission_id)
    grade = get_object_or_404(Grade, submission=submission)
    key = settings.ENCRYPTION_KEY

    # TODO: the encrypt/save block below is nearly identical to grade_submission, could refactor
    try:
        current_score = decrypt_aes_gcm(grade.encrypted_score, key)
        current_feedback = decrypt_aes_gcm(grade.encrypted_feedback, key)
    except Exception:
        current_score = ''
        current_feedback = ''

    if request.method == 'POST':
        form = GradeForm(request.POST)
        if form.is_valid():
            score = str(form.cleaned_data['score'])
            feedback = form.cleaned_data['feedback']

            raw = f"{score}|{feedback}"
            hmac_digest = compute_hmac(raw.encode(), key)
            enc_score = encrypt_aes_gcm(score, key)
            enc_feedback = encrypt_aes_gcm(feedback, key)

            grade.encrypted_score = enc_score
            grade.encrypted_feedback = enc_feedback
            grade.hmac_digest = hmac_digest
            grade.grader = request.user
            grade.save()

            log_event(request.user, 'grade_update',
                      f"Updated grade for submission '{submission.title}' (ID {submission.pk}), "
                      f"student '{submission.student.username}', new score {score}", request)
            messages.success(request, "Grade updated.")
            return redirect('all_submissions')
    else:
        form = GradeForm(initial={'score': current_score, 'feedback': current_feedback})

    return render(request, 'grades/grade_form.html', {
        'form': form,
        'submission': submission,
        'action': 'Update',
    })


@login_required
def my_grades(request):
    submissions = Submission.objects.filter(
        student=request.user
    ).select_related('grade').order_by('-submitted_at')

    key = settings.ENCRYPTION_KEY
    results = []

    for sub in submissions:
        entry = {'submission': sub, 'score': None, 'feedback': None, 'integrity_ok': False}
        if hasattr(sub, 'grade'):
            g = sub.grade
            try:
                score = decrypt_aes_gcm(g.encrypted_score, key)
                feedback = decrypt_aes_gcm(g.encrypted_feedback, key)
                raw = f"{score}|{feedback}"
                integrity_ok = verify_hmac(raw.encode(), key, g.hmac_digest)

                entry['score'] = score
                entry['feedback'] = feedback
                entry['integrity_ok'] = integrity_ok
                entry['graded_at'] = g.graded_at
            except Exception:
                entry['score'] = '[decryption failed]'
                entry['feedback'] = '[decryption failed]'
        results.append(entry)

    return render(request, 'grades/my_grades.html', {'results': results})
