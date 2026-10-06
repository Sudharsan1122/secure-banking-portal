/**
 * SecureBank Beneficiaries Directory Client Script (beneficiaries.js)
 * 
 * PILLAR B [B4]: 2-STEP BENEFICIARY ENROLLMENT & VERIFICATION
 * PILLAR E: FINTECH CARD GRID, MASKED ACCOUNT NUMBERS, MODAL ENROLLMENT
 * 
 * Strict Security Defenses:
 * - textContent used for DOM rendering (XSS defense)
 * - CSRF token verification
 * - Zero inline scripts
 */

document.addEventListener('DOMContentLoaded', async () => {
    const gridContainer = document.getElementById('beneficiaryGridContainer');
    const bCountBadge = document.getElementById('bCountBadge');
    const addForm = document.getElementById('addBeneficiaryForm');
    const addBtn = document.getElementById('addBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const openAddModalBtn = document.getElementById('openAddModalBtn');
    const addModal = document.getElementById('addBeneficiaryModal');
    const closeAddModalBtn = document.getElementById('closeAddModalBtn');
    const cancelAddModalBtn = document.getElementById('cancelAddModalBtn');

    // Modal controls
    function openModal() {
        if (window.SecureBankModal) {
            window.SecureBankModal.open('addBeneficiaryModal');
        } else if (addModal) {
            addModal.classList.add('active');
        }
    }

    function closeModal() {
        if (window.SecureBankModal) {
            window.SecureBankModal.close('addBeneficiaryModal');
        } else if (addModal) {
            addModal.classList.remove('active');
        }
    }

    openAddModalBtn?.addEventListener('click', openModal);
    closeAddModalBtn?.addEventListener('click', closeModal);
    cancelAddModalBtn?.addEventListener('click', closeModal);

    // Sign Out Handler
    logoutBtn?.addEventListener('click', async () => {
        try {
            await fetch('../api/logout.php', { method: 'POST' });
        } finally {
            sessionStorage.clear();
            window.location.href = 'login.html';
        }
    });

    async function loadBeneficiaries() {
        try {
            const res = await fetch('../api/beneficiaries.php');
            if (res.status === 401) {
                window.location.href = 'login.html?msg=expired';
                return;
            }
            const data = await res.json();
            if (data.status === 'success') {
                renderBeneficiaries(data.data);
            }
        } catch (e) {
            console.error('Error loading beneficiaries', e);
        }
    }

    function maskAccount(accNumber) {
        if (!accNumber || accNumber.length < 8) return accNumber;
        return accNumber.substring(0, 4) + '-••••-' + accNumber.substring(accNumber.length - 4);
    }

    function renderBeneficiaries(items) {
        if (!gridContainer) return;
        gridContainer.textContent = '';

        if (bCountBadge) {
            bCountBadge.textContent = `${items.length} Enrolled`;
        }

        // Add Payee Dashed Card
        const addCard = document.createElement('div');
        addCard.className = 'beneficiary-card-add';
        addCard.innerHTML = `
            <div style="width: 44px; height: 44px; border-radius: 50%; background-color: var(--color-secondary-subtle); display: flex; align-items: center; justify-content: center; margin-bottom: var(--space-2); color: var(--color-secondary);">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            </div>
            <strong style="font-size: 0.95rem;">Enroll New Payee</strong>
            <span class="caption" style="color: var(--text-muted); margin-top: 2px;">2-Step OTP Verified</span>
        `;
        addCard.addEventListener('click', openModal);
        gridContainer.appendChild(addCard);

        items.forEach(b => {
            const card = document.createElement('div');
            card.className = 'card card-hover';
            card.style.display = 'flex';
            card.style.flexDirection = 'column';
            card.style.justifyContent = 'space-between';

            const topRow = document.createElement('div');
            topRow.style.display = 'flex';
            topRow.style.justifyContent = 'space-between';
            topRow.style.alignItems = 'flex-start';
            topRow.style.marginBottom = 'var(--space-3)';

            const avatarWrap = document.createElement('div');
            avatarWrap.className = 'avatar avatar-md';
            avatarWrap.style.backgroundColor = b.verified ? 'var(--color-secondary)' : 'var(--color-warning)';
            const initials = b.name.split(' ').map(p => p[0]).join('').substring(0, 2).toUpperCase();
            avatarWrap.textContent = initials;
            topRow.appendChild(avatarWrap);

            const statusBadge = document.createElement('span');
            if (b.verified) {
                statusBadge.className = 'badge badge-success';
                statusBadge.textContent = '✓ Verified';
            } else {
                statusBadge.className = 'badge badge-warning';
                statusBadge.textContent = '⚠️ Unverified';
            }
            topRow.appendChild(statusBadge);
            card.appendChild(topRow);

            const bodyWrap = document.createElement('div');
            bodyWrap.style.marginBottom = 'var(--space-4)';

            const nameEl = document.createElement('h3');
            nameEl.className = 'card-title';
            nameEl.style.fontSize = '1.05rem';
            nameEl.style.marginBottom = '2px';
            nameEl.textContent = b.name;
            bodyWrap.appendChild(nameEl);

            const bankEl = document.createElement('div');
            bankEl.className = 'caption';
            bankEl.style.color = 'var(--text-muted)';
            bankEl.textContent = b.bank_name;
            bodyWrap.appendChild(bankEl);

            const accEl = document.createElement('div');
            accEl.className = 'mono';
            accEl.style.fontSize = '0.8125rem';
            accEl.style.marginTop = 'var(--space-2)';
            accEl.style.color = 'var(--text-secondary)';
            accEl.textContent = maskAccount(b.account_number);
            bodyWrap.appendChild(accEl);

            card.appendChild(bodyWrap);

            const actionsRow = document.createElement('div');
            actionsRow.style.display = 'flex';
            actionsRow.style.gap = 'var(--space-2)';
            actionsRow.style.paddingTop = 'var(--space-3)';
            actionsRow.style.borderTop = '1px solid var(--border-subtle)';

            if (b.verified) {
                const sendBtn = document.createElement('a');
                sendBtn.href = 'transfer.html';
                sendBtn.className = 'btn btn-primary btn-sm btn-block';
                sendBtn.textContent = 'Send Funds';
                actionsRow.appendChild(sendBtn);
            } else {
                const verifyBtn = document.createElement('a');
                verifyBtn.href = `verify_beneficiary.html?id=${b.id}`;
                verifyBtn.className = 'btn btn-secondary btn-sm btn-block';
                verifyBtn.style.color = 'var(--color-warning)';
                verifyBtn.textContent = '🔐 Verify OTP';
                actionsRow.appendChild(verifyBtn);
            }

            card.appendChild(actionsRow);
            gridContainer.appendChild(card);
        });
    }

    // Submit Add Beneficiary Form
    addForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('bName').value.trim();
        const account_number = document.getElementById('bAccount').value.trim();
        const bank_name = document.getElementById('bBank').value.trim();

        if (!name || !account_number || !bank_name) {
            showToast('Please fill in all beneficiary fields.', 'error');
            return;
        }

        addBtn.disabled = true;
        addBtn.textContent = 'Enrolling...';

        try {
            const csrfToken = sessionStorage.getItem('csrf_token') || '';
            const res = await fetch('../api/beneficiaries.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ name, account_number, bank_name })
            });
            const data = await res.json();

            if (res.ok && data.status === 'success') {
                showToast('Beneficiary registered! Redirecting to OTP verification...', 'success');
                closeModal();
                addForm.reset();
                const demoParam = data.demo_otp ? `&otp=${encodeURIComponent(data.demo_otp)}` : '';
                setTimeout(() => {
                    window.location.href = `verify_beneficiary.html?id=${data.id}${demoParam}`;
                }, 1000);
            } else {
                showToast(data.message || 'Failed to add beneficiary.', 'error');
            }
        } catch (err) {
            showToast('Network error enrolling beneficiary.', 'error');
        } finally {
            addBtn.disabled = false;
            addBtn.textContent = 'Enroll Beneficiary';
        }
    });

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

    loadBeneficiaries();
});
