/**
 * Registration Client Script with Live Password Strength Evaluation
 * 
 * SECURITY PRINCIPLES IMPLEMENTED:
 * 1. Client-Side + Server-Side Validation: Immediate UX guidance paired with strict server enforcement.
 * 2. Safe DOM Handling: textContent prevents DOM-based XSS when reflecting user inputs.
 */

document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    const passwordInput = document.getElementById('password');
    const submitBtn = document.getElementById('submitBtn');
    const errorAlert = document.getElementById('errorAlert');

    // Password criteria elements
    const reqLength = document.getElementById('reqLength');
    const reqUpper = document.getElementById('reqUpper');
    const reqLower = document.getElementById('reqLower');
    const reqNumber = document.getElementById('reqNumber');
    const reqSpecial = document.getElementById('reqSpecial');

    // Live password complexity listener
    passwordInput?.addEventListener('input', () => {
        const val = passwordInput.value;
        updateRequirement(reqLength, val.length >= 8);
        updateRequirement(reqUpper, /[A-Z]/.test(val));
        updateRequirement(reqLower, /[a-z]/.test(val));
        updateRequirement(reqNumber, /[0-9]/.test(val));
        updateRequirement(reqSpecial, /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(val));
    });

    function updateRequirement(el, valid) {
        if (!el) return;
        if (valid) {
            el.style.color = '#15803d';
            el.textContent = '✓ ' + el.textContent.replace(/^[✓✗]\s*/, '');
        } else {
            el.style.color = '#dc2626';
            el.textContent = '✗ ' + el.textContent.replace(/^[✓✗]\s*/, '');
        }
    }

    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideError();

        const name = document.getElementById('name').value.trim();
        const email = document.getElementById('email').value.trim();
        const phone = document.getElementById('phone').value.trim();
        const username = document.getElementById('username').value.trim();
        const password = passwordInput.value;

        // Basic front-end sanity check
        if (!name || !email || !phone || !username || !password) {
            showError('All fields are required.');
            return;
        }

        setLoading(true);

        try {
            const response = await fetch('../api/register.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ name, email, phone, username, password })
            });

            const data = await response.json();

            if (response.ok && data.status === 'success') {
                showToast('Registration successful! Redirecting to login...', 'success');
                setTimeout(() => {
                    window.location.href = 'login.html?msg=registered';
                }, 1200);
            } else {
                const errorMsg = data.errors ? data.errors.join(' ') : (data.message || 'Registration failed.');
                showError(errorMsg);
                showToast('Registration error', 'error');
            }
        } catch (error) {
            console.error('Registration error:', error);
            showError('Network error connecting to registration service.');
        } finally {
            setLoading(false);
        }
    });

    function setLoading(isLoading) {
        submitBtn.disabled = isLoading;
        if (isLoading) {
            submitBtn.innerHTML = '<span class="spinner-sm"></span> Creating Account...';
        } else {
            submitBtn.textContent = 'Create Account';
        }
    }

    function showError(msg) {
        if (!errorAlert) return;
        errorAlert.textContent = msg;
        errorAlert.style.display = 'block';
    }

    function hideError() {
        if (!errorAlert) return;
        errorAlert.style.display = 'none';
        errorAlert.textContent = '';
    }

    function showToast(message, type = 'info') {
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
