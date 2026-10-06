/**
 * SecureBank Beneficiary 2-Step OTP Verification Script (verify_beneficiary.js)
 * 
 * PILLAR B [B4]: 2-STEP BENEFICIARY VERIFICATION WITH BCRYPT LOCKOUT
 * PILLAR E: 6-DIGIT AUTO-ADVANCE, DEMO CODE AUTOFILL, ZERO INLINE SCRIPTS
 */

document.addEventListener('DOMContentLoaded', async () => {
    const urlParams = new URLSearchParams(window.location.search);
    const bId = urlParams.get('id');
    const demoCode = urlParams.get('otp');
    const demoOtpAlert = document.getElementById('demoOtpAlert');
    const demoOtpValue = document.getElementById('demoOtpValue');
    const autofillBtn = document.getElementById('autofillBtn');
    const verifyForm = document.getElementById('verifyForm');
    const submitBtn = document.getElementById('submitVerifyBtn');
    const otpBoxes = document.querySelectorAll('.otp-box');

    if (demoCode) {
        if (demoOtpAlert) demoOtpAlert.style.display = 'flex';
        if (demoOtpValue) demoOtpValue.textContent = demoCode;
    }

    if (!bId) {
        if (window.showToast) window.showToast('No beneficiary specified.', 'error');
        setTimeout(() => window.location.href = 'beneficiaries.html', 1200);
        return;
    }

    // Auto-fill demo OTP button
    autofillBtn?.addEventListener('click', () => {
        if (demoCode) {
            demoCode.split('').forEach((d, i) => {
                if (otpBoxes[i]) otpBoxes[i].value = d;
            });
            if (window.showToast) window.showToast('Demo OTP inserted.', 'info');
            checkAutoSubmit();
        }
    });

    // Fetch CSRF token from dashboard if needed
    let csrfToken = sessionStorage.getItem('csrf_token') || '';
    if (!csrfToken) {
        try {
            const res = await fetch('../api/dashboard.php');
            if (res.status === 401) { window.location.href = 'login.html'; return; }
            const data = await res.json();
            if (data.data?.csrf_token) {
                csrfToken = data.data.csrf_token;
                sessionStorage.setItem('csrf_token', csrfToken);
            }
        } catch (e) {
            console.error('CSRF fetch error', e);
        }
    }

    // OTP Box auto-advance & paste
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

        box.addEventListener('paste', (e) => {
            e.preventDefault();
            const paste = (e.clipboardData || window.clipboardData).getData('text').trim();
            const digits = paste.replace(/\D/g, '').slice(0, 6);
            if (digits) {
                digits.split('').forEach((d, i) => {
                    if (otpBoxes[i]) otpBoxes[i].value = d;
                });
                const next = Math.min(digits.length, 5);
                otpBoxes[next].focus();
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
            submitVerification(code);
        }
    }

    verifyForm?.addEventListener('submit', (e) => {
        e.preventDefault();
        const code = getCombinedOtp();
        if (!code || !/^\d{6}$/.test(code)) {
            showToast('Please enter all 6 digits of the OTP.', 'error');
            return;
        }
        submitVerification(code);
    });

    async function submitVerification(otpValue) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner"></span><span>Verifying Payee...</span>';

        try {
            const res = await fetch('../api/verify_beneficiary.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    beneficiary_id: parseInt(bId),
                    otp: otpValue
                })
            });

            const data = await res.json();

            if (res.ok && data.status === 'success') {
                showToast('Beneficiary verified successfully! Redirecting...', 'success');
                setTimeout(() => window.location.href = 'beneficiaries.html', 1200);
            } else {
                showToast(data.message || 'OTP verification failed.', 'error');
                otpBoxes.forEach(b => {
                    b.value = '';
                    b.style.borderColor = 'var(--color-danger)';
                });
                if (otpBoxes[0]) otpBoxes[0].focus();
            }
        } catch (err) {
            showToast('Network error during verification.', 'error');
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<span>Verify & Authorize Payee</span>';
        }
    }

    function showToast(message, type = 'info') {
        if (window.showToast) {
            window.showToast(message, type);
            return;
        }
        const container = document.getElementById('toastContainer');
        if (!container) return;
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => {
            toast.classList.add('toast-fade');
            setTimeout(() => toast.remove(), 300);
        }, 3500);
    }
});
