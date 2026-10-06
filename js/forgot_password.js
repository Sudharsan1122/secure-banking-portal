/**
 * SecureBank Forgot Password Client Script (forgot_password.js)
 * Pillar A [A5]: Secure SHA-256 Token-Based Password Resets
 */
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('forgotForm');
    const submitBtn = document.getElementById('submitBtn');
    const errorAlert = document.getElementById('errorAlert');
    const successAlert = document.getElementById('successAlert');
    const simulatedBox = document.getElementById('simulatedBox');
    const simulatedLink = document.getElementById('simulatedLink');

    form?.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (errorAlert) errorAlert.style.display = 'none';
        if (successAlert) successAlert.style.display = 'none';
        if (simulatedBox) simulatedBox.style.display = 'none';

        const identifier = document.getElementById('identifier').value.trim();
        if (!identifier) return;

        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner"></span><span>Dispatching Token...</span>';

        try {
            const res = await fetch('../api/request_reset.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identifier })
            });
            const data = await res.json();

            if (res.ok && data.status === 'success') {
                if (successAlert) {
                    successAlert.textContent = data.message;
                    successAlert.style.display = 'flex';
                }
                if (data.simulated_link && simulatedLink && simulatedBox) {
                    simulatedLink.href = data.simulated_link;
                    simulatedBox.style.display = 'block';
                }
                if (window.showToast) window.showToast('Reset token generated securely.', 'success');
            } else {
                if (errorAlert) {
                    errorAlert.textContent = data.message || 'Failed to request password reset.';
                    errorAlert.style.display = 'flex';
                }
            }
        } catch (err) {
            if (errorAlert) {
                errorAlert.textContent = 'Network error connecting to password reset service.';
                errorAlert.style.display = 'flex';
            }
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<span>Dispatch Reset Token</span>';
        }
    });
});
