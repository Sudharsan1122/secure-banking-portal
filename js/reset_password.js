/**
 * SecureBank Reset Password Client Script (reset_password.js)
 * Pillar A [A5]: Secure SHA-256 Token-Based Password Resets
 * Pillar E: Fintech-grade Accessible UX
 */
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('resetForm');
    const submitBtn = document.getElementById('submitBtn');
    const errorAlert = document.getElementById('errorAlert');
    const successAlert = document.getElementById('successAlert');
    const tokenInput = document.getElementById('resetToken');
    const tokenPreview = document.getElementById('tokenPreview');

    // Password visibility toggles
    const setupPasswordToggle = (toggleBtnId, inputId) => {
        const btn = document.getElementById(toggleBtnId);
        const input = document.getElementById(inputId);
        if (btn && input) {
            btn.addEventListener('click', () => {
                const isPassword = input.type === 'password';
                input.type = isPassword ? 'text' : 'password';
                btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
                btn.innerHTML = isPassword
                    ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>'
                    : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
            });
        }
    };

    setupPasswordToggle('toggleNewPassBtn', 'newPassword');
    setupPasswordToggle('toggleConfirmPassBtn', 'confirmPassword');

    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');

    if (!token) {
        if (errorAlert) {
            errorAlert.textContent = 'Missing or invalid reset token. Please request a new link.';
            errorAlert.style.display = 'flex';
        }
        if (submitBtn) submitBtn.disabled = true;
        if (tokenPreview) tokenPreview.textContent = 'None provided';
        return;
    }

    if (tokenInput) tokenInput.value = token;
    if (tokenPreview) tokenPreview.textContent = token.substring(0, 16) + '... (SHA-256 Verified)';

    form?.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (errorAlert) {
            errorAlert.style.display = 'none';
            errorAlert.textContent = '';
        }
        if (successAlert) {
            successAlert.style.display = 'none';
            successAlert.textContent = '';
        }

        const new_password = document.getElementById('newPassword').value;
        const confirm_password = document.getElementById('confirmPassword').value;

        if (new_password !== confirm_password) {
            if (errorAlert) {
                errorAlert.textContent = 'Passwords do not match.';
                errorAlert.style.display = 'flex';
            }
            if (window.showToast) window.showToast('Passwords do not match.', 'error');
            return;
        }

        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner"></span><span>Updating Master Password...</span>';

        try {
            const res = await fetch('../api/reset_password.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, new_password })
            });
            const data = await res.json();

            if (res.ok && data.status === 'success') {
                if (successAlert) {
                    successAlert.textContent = data.message || 'Password successfully reset! Redirecting to login...';
                    successAlert.style.display = 'flex';
                }
                form.style.display = 'none';
                if (window.showToast) window.showToast('Password reset complete.', 'success');
                setTimeout(() => window.location.href = 'login.html?msg=password_reset_complete', 1800);
            } else {
                const msg = data.errors ? data.errors.join(' ') : (data.message || 'Failed to reset password.');
                if (errorAlert) {
                    errorAlert.textContent = msg;
                    errorAlert.style.display = 'flex';
                }
                if (window.showToast) window.showToast(msg, 'error');
            }
        } catch (err) {
            if (errorAlert) {
                errorAlert.textContent = 'Network error during password reset.';
                errorAlert.style.display = 'flex';
            }
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<span>Update Password & Terminate Sessions</span>';
        }
    });
});
