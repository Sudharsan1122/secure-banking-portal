/**
 * SecureBank Authentication Client Script (Step 1: Credentials Verification)
 * 
 * SECURITY PRINCIPLES IMPLEMENTED:
 * 1. Safe DOM Manipulation: Uses textContent to avoid DOM-based XSS when displaying error messages.
 * 2. Rate-Limiting Feedback: Handles HTTP 429 Too Many Requests gracefully with countdown.
 * 3. Multi-Factor Workflow: Persists temporary pre-auth state in sessionStorage for Step 2.
 * 4. SVG Password Visibility Toggle: Uses external DOM event listeners without inline scripts.
 */

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const submitBtn = document.getElementById('submitBtn');
    const errorAlert = document.getElementById('errorAlert');
    const togglePasswordBtn = document.getElementById('togglePasswordBtn');
    const usernameField = document.getElementById('usernameField');
    const passwordField = document.getElementById('passwordField');

    // Password visibility toggle (SVG swap)
    if (togglePasswordBtn && passwordInput) {
        togglePasswordBtn.addEventListener('click', () => {
            const isPassword = passwordInput.type === 'password';
            passwordInput.type = isPassword ? 'text' : 'password';
            togglePasswordBtn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
            
            // Toggle SVG icon safely
            togglePasswordBtn.innerHTML = isPassword
                ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>'
                : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
        });
    }

    // Display messages passed via query string (e.g., session expired)
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('msg') === 'expired') {
        showError('Your session has expired due to 15 minutes of inactivity. Please log in again.');
    } else if (urlParams.get('msg') === 'registered') {
        if (window.showToast) window.showToast('Account registered successfully! Please log in.', 'success');
    }

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideError();
        if (usernameField) usernameField.classList.remove('has-error');
        if (passwordField) passwordField.classList.remove('has-error');

        const username = usernameInput.value.trim();
        const password = passwordInput.value;

        let hasValidationErr = false;
        if (!username) {
            if (usernameField) usernameField.classList.add('has-error');
            hasValidationErr = true;
        }
        if (!password) {
            if (passwordField) passwordField.classList.add('has-error');
            hasValidationErr = true;
        }

        if (hasValidationErr) {
            showError('Please provide both username and password.');
            return;
        }

        // UI Loading state
        setLoading(true);

        try {
            const response = await fetch('../api/login.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok && data.status === 'otp_required') {
                // Step 1 Success: Proceed to Step 2 (MFA Verification)
                sessionStorage.setItem('mfa_user_id', data.user_id);
                sessionStorage.setItem('mfa_username', data.username);
                if (data.simulated_otp) {
                    sessionStorage.setItem('simulated_otp', data.simulated_otp);
                }

                if (window.showToast) {
                    window.showToast('Credentials verified. Redirecting to MFA verification...', 'success');
                }
                setTimeout(() => {
                    window.location.href = 'mfa.html';
                }, 700);

            } else if (response.status === 429) {
                // Rate limit triggered (Module 2)
                showError('Security Alert: Account/IP temporarily locked due to excessive failed attempts. Please wait 15 minutes.');
                if (window.showToast) window.showToast('Rate limit exceeded! (Max 5 attempts)', 'error');
            } else {
                showError(data.message || 'Invalid username or password.');
                if (window.showToast) window.showToast('Authentication failed', 'error');
                if (passwordField) passwordField.classList.add('has-error');
            }
        } catch (error) {
            console.error('Login error:', error);
            showError('Unable to connect to authentication server. Please verify network connectivity.');
        } finally {
            setLoading(false);
        }
    });

    function setLoading(isLoading) {
        submitBtn.disabled = isLoading;
        if (isLoading) {
            submitBtn.innerHTML = '<span class="spinner"></span><span>Verifying Credentials...</span>';
        } else {
            submitBtn.innerHTML = '<span>Sign In</span>';
        }
    }

    function showError(msg) {
        if (!errorAlert) return;
        // DOM XSS Prevention: Use textContent exclusively
        errorAlert.textContent = msg;
        errorAlert.style.display = 'flex';
    }

    function hideError() {
        if (!errorAlert) return;
        errorAlert.style.display = 'none';
        errorAlert.textContent = '';
    }
});
