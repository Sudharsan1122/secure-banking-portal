/**
 * SecureBank MFA Verification Client Script (mfa.js)
 * Pillar E — 6 Separate OTP Boxes with Auto-Advance, Paste Handling, Countdown & Theme
 * 
 * Strict Security Defenses:
 * - textContent used for DOM injection (XSS defense)
 * - Session regeneration on successful 2FA
 * - CSRF token initialization
 */

document.addEventListener('DOMContentLoaded', () => {
    const mfaForm = document.getElementById('mfaForm');
    const otpBoxes = document.querySelectorAll('.otp-box');
    const submitBtn = document.getElementById('submitBtn');
    const errorAlert = document.getElementById('errorAlert');
    const mfaPrompt = document.getElementById('mfaPrompt');
    const simulatedOtpCode = document.getElementById('simulatedOtpCode');
    const autofillBtn = document.getElementById('autofillBtn');
    const resendTimerEl = document.getElementById('resendTimer');
    const recoveryToggle = document.getElementById('recoveryToggle');
    const recoveryField = document.getElementById('recoveryField');
    const recoveryCodeInput = document.getElementById('recoveryCodeInput');

    const userId = sessionStorage.getItem('mfa_user_id');
    const username = sessionStorage.getItem('mfa_username');
    const simOtp = sessionStorage.getItem('simulated_otp');

    if (!userId) {
        window.location.href = 'login.html';
        return;
    }

    if (username && mfaPrompt) {
        mfaPrompt.textContent = `Authenticating: ${username}`;
    }

    if (simOtp && simulatedOtpCode) {
        simulatedOtpCode.textContent = simOtp;
    }

    // Auto-advance between 6 OTP boxes
    otpBoxes.forEach((box, index) => {
        box.addEventListener('input', (e) => {
            const val = e.target.value.replace(/\D/g, '');
            e.target.value = val ? val[0] : '';
            if (val && index < otpBoxes.length - 1) {
                otpBoxes[index + 1].focus();
            }
            checkAutoSubmit();
        });

        box.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !box.value && index > 0) {
                otpBoxes[index - 1].focus();
            }
        });

        // Handle Paste (e.g. user pastes 6-digit code)
        box.addEventListener('paste', (e) => {
            e.preventDefault();
            const pasteData = (e.clipboardData || window.clipboardData).getData('text').trim();
            const digits = pasteData.replace(/\D/g, '').slice(0, 6);
            if (digits) {
                digits.split('').forEach((d, i) => {
                    if (otpBoxes[i]) otpBoxes[i].value = d;
                });
                const nextFocus = Math.min(digits.length, 5);
                otpBoxes[nextFocus].focus();
                checkAutoSubmit();
            }
        });
    });

    function getCombinedOtp() {
        return Array.from(otpBoxes).map(b => b.value).join('');
    }

    function checkAutoSubmit() {
        const code = getCombinedOtp();
        if (code.length === 6) {
            submitOtp(code);
        }
    }

    // Autofill demo button
    if (autofillBtn && simOtp) {
        autofillBtn.addEventListener('click', () => {
            simOtp.split('').forEach((digit, i) => {
                if (otpBoxes[i]) otpBoxes[i].value = digit;
            });
            if (window.showToast) window.showToast('Demo OTP code auto-filled.', 'info');
            checkAutoSubmit();
        });
    }

    // Resend countdown timer
    let timeLeft = 60;
    const timerInterval = setInterval(() => {
        timeLeft--;
        if (timeLeft <= 0) {
            clearInterval(timerInterval);
            if (resendTimerEl) resendTimerEl.textContent = 'Resend Code Available';
        } else {
            const min = Math.floor(timeLeft / 60);
            const sec = timeLeft % 60;
            if (resendTimerEl) {
                resendTimerEl.textContent = `Resend in ${min}:${sec < 10 ? '0' : ''}${sec}`;
            }
        }
    }, 1000);

    // Toggle Recovery Code Mode
    if (recoveryToggle && recoveryField) {
        recoveryToggle.addEventListener('click', (e) => {
            e.preventDefault();
            const isHidden = recoveryField.style.display === 'none';
            recoveryField.style.display = isHidden ? 'block' : 'none';
            recoveryToggle.textContent = isHidden ? 'Enter standard 6-digit OTP' : 'Use emergency recovery code instead';
            if (isHidden && recoveryCodeInput) {
                recoveryCodeInput.focus();
            }
        });
    }

    mfaForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const recoveryCode = recoveryCodeInput && recoveryField && recoveryField.style.display !== 'none'
            ? recoveryCodeInput.value.trim()
            : null;

        if (recoveryCode) {
            submitOtp(recoveryCode, true);
        } else {
            const otp = getCombinedOtp();
            if (!otp || !/^\d{6}$/.test(otp)) {
                showError('Please enter all 6 digits of your one-time passcode.');
                return;
            }
            submitOtp(otp, false);
        }
    });

    async function submitOtp(otpValue, isRecovery = false) {
        hideError();
        setLoading(true);

        try {
            const payload = { user_id: userId, otp: otpValue };
            if (isRecovery) {
                payload.is_recovery = true;
            }

            const response = await fetch('../api/verify_otp.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (response.ok && data.status === 'success') {
                // Clean up temporary MFA session storage
                sessionStorage.removeItem('mfa_user_id');
                sessionStorage.removeItem('mfa_username');
                sessionStorage.removeItem('simulated_otp');

                // Save CSRF token and user metadata
                sessionStorage.setItem('csrf_token', data.csrf_token);
                sessionStorage.setItem('user', JSON.stringify(data.user));

                if (window.showToast) {
                    window.showToast('MFA verification successful! Regenerating session...', 'success');
                }

                setTimeout(() => {
                    if (data.user && data.user.role === 'admin') {
                        window.location.href = '../admin/security-dashboard.php';
                    } else {
                        window.location.href = 'dashboard.html';
                    }
                }, 800);
            } else {
                showError(data.message || 'MFA verification failed. Please try again.');
                if (window.showToast) window.showToast('Invalid or expired MFA code', 'error');
                otpBoxes.forEach(b => {
                    b.value = '';
                    b.style.borderColor = 'var(--color-danger)';
                });
                if (otpBoxes[0]) otpBoxes[0].focus();
            }
        } catch (err) {
            console.error('MFA error:', err);
            showError('Network error connecting to verification service.');
        } finally {
            setLoading(false);
        }
    }

    function setLoading(isLoading) {
        submitBtn.disabled = isLoading;
        if (isLoading) {
            submitBtn.innerHTML = '<span class="spinner"></span><span>Verifying OTP...</span>';
        } else {
            submitBtn.innerHTML = '<span>Verify & Establish Secure Session</span>';
        }
    }

    function showError(msg) {
        if (!errorAlert) return;
        errorAlert.textContent = msg;
        errorAlert.style.display = 'flex';
    }

    function hideError() {
        if (!errorAlert) return;
        errorAlert.style.display = 'none';
        errorAlert.textContent = '';
    }
});
