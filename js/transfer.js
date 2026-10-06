/**
 * SecureBank Money Transfer Client Script (transfer.js)
 * 
 * MODULE 4: MONEY TRANSFER
 * MODULE 5: XSS TESTING SHORTCUTS
 * MODULE 6: CSRF HEADER INJECTION
 * PILLAR B [B1]: TRANSACTION CATEGORIES
 * PILLAR B [B5]: VELOCITY LIMIT ENFORCEMENT
 * PILLAR B [B6]: MULTI-ACCOUNT DEBIT SELECTION
 * PILLAR E: DYNAMIC AMOUNT SUBMIT BUTTON, CATEGORY CHIPS, COLLAPSIBLE DEMO CONTROLS
 */

document.addEventListener('DOMContentLoaded', async () => {
    const transferForm = document.getElementById('transferForm');
    const fromAccountSelect = document.getElementById('fromAccountSelect');
    const beneficiarySelect = document.getElementById('beneficiarySelect');
    const categorySelect = document.getElementById('categorySelect');
    const accountInput = document.getElementById('accountNumber');
    const amountInput = document.getElementById('amount');
    const remarkInput = document.getElementById('remark');
    const submitBtn = document.getElementById('submitBtn');
    const submitBtnText = document.getElementById('submitBtnText');
    const currentBalanceEl = document.getElementById('currentBalance');
    const logoutBtn = document.getElementById('logoutBtn');
    const unreadNotifBadge = document.getElementById('unreadNotifBadge');
    const maxAmountBtn = document.getElementById('maxAmountBtn');
    const velocityWarning = document.getElementById('velocityWarning');

    let userAccounts = [];
    let activeAccountBalance = 0;
    let csrfToken = sessionStorage.getItem('csrf_token') || '';

    // Collapsible Accordion Toggle
    document.querySelectorAll('[data-collapsible-toggle]').forEach(trigger => {
        trigger.addEventListener('click', () => {
            const parent = trigger.closest('.collapsible');
            if (parent) parent.classList.toggle('open');
        });
    });

    // Category Chips Selection
    const categoryChips = document.querySelectorAll('#categoryChips .chip');
    categoryChips.forEach(chip => {
        chip.addEventListener('click', () => {
            categoryChips.forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            if (categorySelect) {
                categorySelect.value = chip.getAttribute('data-category');
            }
        });
    });

    // Max Amount Click
    if (maxAmountBtn && amountInput) {
        maxAmountBtn.addEventListener('click', () => {
            if (activeAccountBalance > 0) {
                amountInput.value = activeAccountBalance.toFixed(2);
                updateSubmitButtonAmount();
            }
        });
    }

    // Dynamic submit button amount display & velocity warning
    function updateSubmitButtonAmount() {
        const amt = parseFloat(amountInput.value);
        if (!isNaN(amt) && amt > 0) {
            if (submitBtnText) {
                submitBtnText.textContent = `Transfer $${amt.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
            }
            if (amt > 50000 && velocityWarning) {
                velocityWarning.style.display = 'block';
            } else if (velocityWarning) {
                velocityWarning.style.display = 'none';
            }
        } else {
            if (submitBtnText) submitBtnText.textContent = 'Authorize & Send Transfer';
            if (velocityWarning) velocityWarning.style.display = 'none';
        }
    }

    amountInput?.addEventListener('input', updateSubmitButtonAmount);

    // Demo Payload Controls
    const demoXssBtn = document.getElementById('demoXssPayloadBtn');
    const demoOverflowBtn = document.getElementById('demoOverflowPayloadBtn');

    if (demoXssBtn && remarkInput) {
        demoXssBtn.addEventListener('click', () => {
            remarkInput.value = '<script>alert("XSS Defeated")</script>';
            if (window.showToast) window.showToast('XSS test payload inserted into remark field.', 'info');
        });
    }

    if (demoOverflowBtn && amountInput) {
        demoOverflowBtn.addEventListener('click', () => {
            amountInput.value = '150000.00';
            updateSubmitButtonAmount();
            if (window.showToast) window.showToast('Limit-breach amount inserted for velocity testing.', 'warning');
        });
    }

    // Sign Out Handler
    logoutBtn?.addEventListener('click', async () => {
        try {
            await fetch('../api/logout.php', { method: 'POST' });
        } finally {
            sessionStorage.clear();
            window.location.href = 'login.html';
        }
    });

    // 1. Initial State Fetch: Load Accounts, Balance, CSRF token, and Beneficiary List
    try {
        const [dashRes, bRes] = await Promise.all([
            fetch('../api/dashboard.php', { headers: { 'Accept': 'application/json' } }),
            fetch('../api/beneficiaries.php', { headers: { 'Accept': 'application/json' } })
        ]);

        if (dashRes.status === 401) {
            window.location.href = 'login.html?msg=expired';
            return;
        }

        const dashData = await dashRes.json();
        if (dashData.status === 'success') {
            csrfToken = dashData.data.csrf_token;
            sessionStorage.setItem('csrf_token', csrfToken);

            userAccounts = dashData.data.accounts || [];

            // Populate source account dropdown (B6)
            if (fromAccountSelect && userAccounts.length > 0) {
                fromAccountSelect.textContent = '';
                userAccounts.forEach(acc => {
                    const opt = document.createElement('option');
                    opt.value = acc.id;
                    opt.dataset.balance = acc.balance;
                    opt.textContent = `${acc.nickname || acc.type.toUpperCase()} (${acc.account_number}) - $${parseFloat(acc.balance).toFixed(2)}`;
                    fromAccountSelect.appendChild(opt);
                });

                activeAccountBalance = parseFloat(userAccounts[0].balance);
            } else {
                activeAccountBalance = parseFloat(dashData.data.user.balance);
            }

            updateBalanceDisplay();
        }

        // Beneficiary Directory (B4: only verified shown or flagged)
        const bData = await bRes.json();
        if (bData.status === 'success' && beneficiarySelect) {
            bData.data.forEach(b => {
                const opt = document.createElement('option');
                opt.value = b.id;
                opt.dataset.account = b.account_number;
                opt.dataset.verified = b.verified ? '1' : '0';
                opt.textContent = `${b.name} (${b.account_number}) ${b.verified ? '✓' : '⚠️ (Unverified)'}`;
                beneficiarySelect.appendChild(opt);
            });
        }
    } catch (err) {
        console.error('Failed to initialize transfer view:', err);
    }

    // 2. Load Notification Badge (B7)
    try {
        const notifRes = await fetch('../api/notifications.php');
        if (notifRes.ok) {
            const notifJson = await notifRes.json();
            if (notifJson.status === 'success' && notifJson.unread_count > 0 && unreadNotifBadge) {
                unreadNotifBadge.style.display = 'block';
            }
        }
    } catch (e) {
        console.error('Failed to load notifications count', e);
    }

    // Update active balance when source account selection changes
    fromAccountSelect?.addEventListener('change', () => {
        const selected = fromAccountSelect.options[fromAccountSelect.selectedIndex];
        if (selected && selected.dataset.balance) {
            activeAccountBalance = parseFloat(selected.dataset.balance);
            updateBalanceDisplay();
        }
    });

    function updateBalanceDisplay() {
        if (currentBalanceEl) {
            currentBalanceEl.textContent = `$${activeAccountBalance.toLocaleString('en-US', {
                minimumFractionDigits: 2,
                maximumFractionDigits: 2
            })} USD`;
        }
    }

    // Auto-fill account number when selecting a saved beneficiary
    beneficiarySelect?.addEventListener('change', () => {
        const selected = beneficiarySelect.options[beneficiarySelect.selectedIndex];
        if (selected && selected.dataset.account) {
            accountInput.value = selected.dataset.account;
            if (selected.dataset.verified === '0') {
                showToast('Notice: This beneficiary is unverified. You must verify them with OTP before transferring.', 'warning');
            }
        } else {
            accountInput.value = '';
        }
    });

    // 3. Submit Transfer Request
    transferForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const from_account_id = fromAccountSelect ? parseInt(fromAccountSelect.value) : null;
        const beneficiary_id  = parseInt(beneficiarySelect.value) || null;
        const category        = categorySelect ? categorySelect.value : 'Transfer';
        const account_number  = accountInput.value.trim();
        const amount          = parseFloat(amountInput.value);
        const remark          = remarkInput.value.trim();

        if (isNaN(amount) || amount <= 0) {
            showToast('Please enter a valid positive transfer amount.', 'error');
            return;
        }

        if (amount > activeAccountBalance) {
            showToast(`Transfer amount ($${amount.toFixed(2)}) exceeds selected account balance ($${activeAccountBalance.toFixed(2)}).`, 'error');
            return;
        }

        submitBtn.disabled = true;
        if (submitBtnText) submitBtnText.textContent = 'Processing Transfer...';

        try {
            const response = await fetch('../api/transfer.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    from_account_id: from_account_id,
                    account_number: account_number,
                    beneficiary_id: beneficiary_id,
                    category: category,
                    amount: amount,
                    remark: remark,
                    csrf_token: csrfToken
                })
            });

            const data = await response.json();

            if (response.ok && data.status === 'success') {
                showToast(`Success! Transferred $${amount.toFixed(2)} to ${account_number}.`, 'success');
                activeAccountBalance = parseFloat(data.new_balance);
                updateBalanceDisplay();
                transferForm.reset();
                updateSubmitButtonAmount();

                setTimeout(() => {
                    window.location.href = 'transactions.html';
                }, 1500);
            } else {
                showToast(data.message || 'Transfer rejected by security controls.', 'error');
            }
        } catch (err) {
            console.error('Transfer submission error:', err);
            showToast('Network error processing transfer.', 'error');
        } finally {
            submitBtn.disabled = false;
            updateSubmitButtonAmount();
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
        }, 4000);
    }
});
