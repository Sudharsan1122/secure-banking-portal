/**
 * SecureBank Audit Chain Inspector Client Script (admin_verify_chain.js)
 * Pillar A [A12] & Pillar C: Cryptographic Hash Chain Verification & Tamper Simulation
 */

document.addEventListener('DOMContentLoaded', () => {
    const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
    const resBox = document.getElementById('actionResult');

    async function triggerAction(actionName) {
        if (!resBox) return;
        resBox.style.display = 'block';
        resBox.className = 'alert alert-info';
        resBox.textContent = 'Processing cryptographic request...';

        try {
            const res = await fetch('verify_log_chain.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': CSRF_TOKEN
                },
                body: JSON.stringify({ action: actionName })
            });
            const json = await res.json();
            if (json.status === 'success') {
                resBox.className = 'alert alert-success';
                resBox.textContent = json.message;
                setTimeout(() => window.location.reload(), 1500);
            } else {
                resBox.className = 'alert alert-danger';
                resBox.textContent = json.message || 'Operation failed';
            }
        } catch (err) {
            resBox.className = 'alert alert-danger';
            resBox.textContent = 'Network or server error executing operation.';
        }
    }

    document.getElementById('btnTamper')?.addEventListener('click', () => triggerAction('simulate_tamper'));
    document.getElementById('btnRepair')?.addEventListener('click', () => triggerAction('repair_chain'));
});
