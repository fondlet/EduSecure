"""
EduSecure cryptographic utilities.

Implements AES-256-GCM for authenticated encryption and HMAC-SHA256 for
integrity verification.  The original coursework script (aes_encryption.py)
used AES-ECB, which is insecure — ECB encrypts identical plaintext blocks to
identical ciphertext blocks, leaking data patterns.  GCM mode adds a random
nonce and an authentication tag that detects any tampering.

Algorithm selection rationale (Assignment Task B — cryptographic controls):
  • AES-256-GCM : symmetric, fast, authenticated — protects submission content
  • HMAC-SHA256  : keyed hash — guarantees integrity of stored grade records
"""

import os
import hmac
import hashlib
import base64
import json

from Crypto.Cipher import AES


# ── AES-256-GCM ──────────────────────────────────────────────────────────────

def encrypt_aes_gcm(plaintext: str, key: bytes) -> str:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns a JSON-encoded string containing base64 fields:
      nonce      — 16-byte random IV (never reused)
      ciphertext — encrypted payload
      tag        — 16-byte GCM authentication tag

    The tag lets the receiver detect any modification before decryption,
    providing confidentiality + integrity in one step.
    """
    nonce = os.urandom(16)                          # random nonce — never reuse
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

    return json.dumps({
        'nonce':      base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag':        base64.b64encode(tag).decode(),
    })


def decrypt_aes_gcm(token: str, key: bytes) -> str:
    """
    Decrypt an AES-256-GCM token produced by encrypt_aes_gcm.

    Raises ValueError if the authentication tag fails — meaning the
    ciphertext has been tampered with.  This maps directly to the
    assignment's requirement to detect modified submission files.
    """
    data = json.loads(token)
    nonce      = base64.b64decode(data['nonce'])
    ciphertext = base64.b64decode(data['ciphertext'])
    tag        = base64.b64decode(data['tag'])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)   # raises on tamper
    return plaintext.decode('utf-8')


# ── HMAC-SHA256 ───────────────────────────────────────────────────────────────

def compute_hmac(data: bytes, key: bytes) -> str:
    """
    Return the HMAC-SHA256 hex digest of *data* under *key*.

    Used to sign grade records so any in-transit modification is detectable.
    The manual TOTP script (totp.py) demonstrates the raw HMAC-SHA1 maths;
    here we use SHA-256 for stronger collision resistance.
    """
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(data: bytes, key: bytes, expected: str) -> bool:
    """
    Constant-time comparison to verify an HMAC — prevents timing attacks.
    Returns True only if the digest matches exactly.
    """
    actual = compute_hmac(data, key)
    return hmac.compare_digest(actual, expected)
