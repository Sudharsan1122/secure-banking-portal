/**
 * SecureBank Admin Users Client Logic (admin_users.js)
 * Pillar B [B9]: Admin User Management, Account Freezing, Limit Control
 */

document.addEventListener('DOMContentLoaded', () => {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

    // Delegated click handler for user table actions
    document.addEventListener('click', async (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;

        const action = btn.getAttribute('data-action');
        const userId = btn.getAttribute('data-user-id');

        if (action === 'freeze') {
            const shouldFreeze = btn.getAttribute('data-frozen') === 'true';
            const actionText = shouldFreeze ? 'FREEZE' : 'UNFREEZE';
            if (!confirm(`Are you sure you want to ${actionText} account #${userId}?`)) return;

            btn.disabled = true;
            try {
                const res = await fetch('api/freeze_user.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ user_id: parseInt(userId, 10), freeze: shouldFreeze })
                });
                const data = await res.json();
                if (res.ok && data.status === 'success') {
                    showToast(data.message, 'success');
                    setTimeout(() => location.reload(), 600);
                } else {
                    showToast(data.message || 'Operation failed.', 'error');
                    btn.disabled = false;
                }
            } catch (err) {
                showToast('Network error during freeze toggle.', 'error');
                btn.disabled = false;
            }
        } else if (action === 'limits') {
            const curSingle = btn.getAttribute('data-single') || '100000';
            const curDaily = btn.getAttribute('data-daily') || '200000';
            const curMonthly = btn.getAttribute('data-monthly') || '1000000';

            const single = prompt('Enter Single Transaction Limit ($):', curSingle);
            if (single === null) return;
            const daily = prompt('Enter Daily Aggregate Limit ($):', curDaily);
            if (daily === null) return;
            const monthly = prompt('Enter 30-Day Aggregate Limit ($):', curMonthly);
            if (monthly === null) return;

            btn.disabled = true;
            try {
                const res = await fetch('api/update_limits.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({
                        user_id: parseInt(userId, 10),
                        limit_single: parseFloat(single),
                        limit_daily: parseFloat(daily),
                        limit_monthly: parseFloat(monthly)
                    })
                });
                const data = await res.json();
                if (res.ok && data.status === 'success') {
                    showToast(data.message, 'success');
                    setTimeout(() => location.reload(), 600);
                } else {
                    showToast(data.message || 'Failed to update velocity limits.', 'error');
                    btn.disabled = false;
                }
            } catch (err) {
                showToast('Network error updating limits.', 'error');
                btn.disabled = false;
            }
        } else if (action === 'reset') {
            const username = btn.getAttribute('data-username') || 'user';
            if (!confirm(`Force password reset for '${username}'? Prior password reset tokens will be invalidated.`)) return;

            btn.disabled = true;
            try {
                const res = await fetch('api/force_reset.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ user_id: parseInt(userId, 10) })
                });
                const data = await res.json();
                if (res.ok && data.status === 'success') {
                    alert(`Reset Link generated:\n${window.location.origin}${data.reset_url}`);
                    showToast(data.message, 'success');
                } else {
                    showToast(data.message || 'Failed to initiate reset.', 'error');
                }
            } catch (err) {
                showToast('Network error during force reset.', 'error');
            } finally {
                btn.disabled = false;
            }
        }
    });

    // Sign Out
    document.getElementById('logoutBtn')?.addEventListener('click', async () => {
        try {
            await fetch('../api/logout.php', { method: 'POST' });
        } finally {
            window.location.href = '../frontend/login.html';
        }
    });

    function showToast(msg, type = 'info') {
        const c = document.getElementById('toastContainer');
        if (!c) return;
        const t = document.createElement('div');
        t.className = `toast toast-${type}`;
        t.textContent = msg;
        c.appendChild(t);
        setTimeout(() => {
            t.classList.add('toast-fade');
            setTimeout(() => t.remove(), 300);
        }, 3000);
    }
});
