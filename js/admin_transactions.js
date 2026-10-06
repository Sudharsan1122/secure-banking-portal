/**
 * SecureBank Admin Transactions Client Logic (admin_transactions.js)
 * Pillar B [B10]: Transaction Monitoring & Heuristic Triage Adjudication
 */

document.addEventListener('DOMContentLoaded', () => {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

    // Delegated click handler for transaction triage adjudication
    document.addEventListener('click', async (e) => {
        const btn = e.target.closest('[data-action="adjudicate"]');
        if (!btn) return;

        const reviewId = btn.getAttribute('data-review-id');
        const outcome = btn.getAttribute('data-outcome');

        const notes = prompt(
            `Enter SOC investigation notes to mark this case as ${outcome.toUpperCase()}:`,
            `Adjudicated as ${outcome} after auditor review.`
        );
        if (notes === null) return;

        btn.disabled = true;
        try {
            const res = await fetch('api/review_transaction.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    review_id: parseInt(reviewId, 10),
                    outcome: outcome,
                    notes: notes
                })
            });
            const data = await res.json();
            if (res.ok && data.status === 'success') {
                showToast(data.message, 'success');
                setTimeout(() => location.reload(), 600);
            } else {
                showToast(data.message || 'Adjudication failed.', 'error');
                btn.disabled = false;
            }
        } catch (err) {
            showToast('Network error during review submission.', 'error');
            btn.disabled = false;
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
