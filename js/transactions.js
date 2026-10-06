/**
 * SecureBank Transactions & Statement Audit Client Script (transactions.js)
 * 
 * MODULE 5: XSS CONTRAST DEMONSTRATOR
 * MODULE 9: DIRECTORY TRAVERSAL PREVENTATIVE TESTING
 * PILLAR B [B1]: TRANSACTION CATEGORIES FILTERING
 * PILLAR B [B3]: STATEMENT EXPORT (CSV + PDF) WITH CWE-1236 MITIGATION
 * PILLAR E: ACCESSIBLE EXPORT MODAL, COLLAPSIBLE ACCORDION, CATEGORY PILLS
 */

document.addEventListener('DOMContentLoaded', async () => {
    const transactionsTableBody = document.getElementById('fullTransactionsTableBody');
    const searchInput = document.getElementById('searchQuery');
    const categoryFilter = document.getElementById('categoryFilter');
    const exportAccount = document.getElementById('exportAccount');
    const exportStart = document.getElementById('exportStart');
    const exportEnd = document.getElementById('exportEnd');
    const exportFormat = document.getElementById('exportFormat');
    const exportForm = document.getElementById('exportForm');
    const logoutBtn = document.getElementById('logoutBtn');
    const unreadNotifBadge = document.getElementById('unreadNotifBadge');
    const recordCountBadge = document.getElementById('recordCountBadge');

    // Export Modal Controls
    const openExportModalBtn = document.getElementById('openExportModalBtn');
    const exportModal = document.getElementById('exportModal');
    const closeExportModalBtn = document.getElementById('closeExportModalBtn');
    const cancelExportModalBtn = document.getElementById('cancelExportModalBtn');

    function openModal() {
        if (window.SecureBankModal) {
            window.SecureBankModal.open('exportModal');
        } else if (exportModal) {
            exportModal.classList.add('active');
        }
    }

    function closeModal() {
        if (window.SecureBankModal) {
            window.SecureBankModal.close('exportModal');
        } else if (exportModal) {
            exportModal.classList.remove('active');
        }
    }

    openExportModalBtn?.addEventListener('click', openModal);
    closeExportModalBtn?.addEventListener('click', closeModal);
    cancelExportModalBtn?.addEventListener('click', closeModal);

    // Collapsible Accordion Toggle
    document.querySelectorAll('[data-collapsible-toggle]').forEach(trigger => {
        trigger.addEventListener('click', () => {
            const parent = trigger.closest('.collapsible');
            if (parent) parent.classList.toggle('open');
        });
    });

    // Sign Out Handler
    logoutBtn?.addEventListener('click', async () => {
        try {
            await fetch('../api/logout.php', { method: 'POST' });
        } finally {
            sessionStorage.clear();
            window.location.href = 'login.html';
        }
    });

    // Default dates for statement export (last 30 days)
    const now = new Date();
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(now.getDate() - 30);

    if (exportEnd) exportEnd.value = now.toISOString().split('T')[0];
    if (exportStart) exportStart.value = thirtyDaysAgo.toISOString().split('T')[0];

    // 1. Fetch user accounts to populate export dropdown
    try {
        const dashRes = await fetch('../api/dashboard.php');
        if (dashRes.status === 401) { window.location.href = 'login.html'; return; }
        const dashData = await dashRes.json();

        if (dashData.status === 'success' && exportAccount) {
            exportAccount.textContent = '';
            (dashData.data.accounts || []).forEach(acc => {
                const opt = document.createElement('option');
                opt.value = acc.id;
                opt.textContent = `${acc.nickname || acc.type.toUpperCase()} (${acc.account_number})`;
                exportAccount.appendChild(opt);
            });
        }
    } catch (e) {
        console.error('Failed to load accounts for export', e);
    }

    // 2. Fetch Notifications Badge (B7)
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

    // 3. Load Transactions
    async function loadTransactions() {
        const query = searchInput ? searchInput.value.trim() : '';
        const cat = categoryFilter ? categoryFilter.value : 'all';

        try {
            let url = `../api/transactions.php?search=${encodeURIComponent(query)}&category=${encodeURIComponent(cat)}`;

            const res = await fetch(url, { headers: { 'Accept': 'application/json' } });
            if (res.status === 401) {
                window.location.href = 'login.html?msg=expired';
                return;
            }

            const json = await res.json();
            if (res.ok && json.status === 'success') {
                renderTransactionRows(json.data);
                if (recordCountBadge) {
                    recordCountBadge.textContent = `${json.data.length} records found`;
                }
            } else {
                showToast(json.message || 'Failed to load transaction history', 'error');
            }
        } catch (err) {
            console.error('Transactions fetch error:', err);
            showToast('Network error fetching transactions.', 'error');
        }
    }

    /**
     * MODULE 5: SECURE DOM RENDERING (textContent Defense)
     */
    function renderTransactionRows(txns) {
        if (!transactionsTableBody) return;
        transactionsTableBody.textContent = '';

        if (!txns || txns.length === 0) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 7;
            cell.className = 'text-center text-muted';
            cell.style.padding = 'var(--space-8)';
            cell.textContent = 'No matching transaction records found.';
            row.appendChild(cell);
            transactionsTableBody.appendChild(row);
            return;
        }

        txns.forEach(t => {
            const tr = document.createElement('tr');

            // 1. ID
            const tdId = document.createElement('td');
            tdId.className = 'mono';
            tdId.style.fontSize = '0.75rem';
            tdId.style.color = 'var(--text-muted)';
            tdId.textContent = `#${t.id}`;
            tr.appendChild(tdId);

            // 2. Date
            const tdDate = document.createElement('td');
            tdDate.className = 'mono';
            tdDate.style.fontSize = '0.8125rem';
            tdDate.style.whiteSpace = 'nowrap';
            tdDate.textContent = t.created_at;
            tr.appendChild(tdDate);

            // 3. Type
            const tdType = document.createElement('td');
            const badge = document.createElement('span');
            badge.className = `badge ${t.type === 'DEBIT' ? 'badge-danger' : 'badge-success'}`;
            badge.textContent = t.type;
            tdType.appendChild(badge);
            tr.appendChild(tdType);

            // 4. Counterparty
            const tdParty = document.createElement('td');
            tdParty.style.fontWeight = '500';
            tdParty.textContent = `${t.counterparty} (${t.counterparty_username})`;
            tr.appendChild(tdParty);

            // 5. Category (B1)
            const tdCat = document.createElement('td');
            const catBadge = document.createElement('span');
            catBadge.className = 'badge badge-neutral';
            catBadge.textContent = t.category || 'Transfer';
            tdCat.appendChild(catBadge);
            tr.appendChild(tdCat);

            // 6. Amount
            const tdAmount = document.createElement('td');
            tdAmount.className = `tabular-nums text-right ${t.type === 'DEBIT' ? 'text-debit' : 'text-credit'}`;
            tdAmount.style.fontWeight = '600';
            tdAmount.textContent = `${t.type === 'DEBIT' ? '-' : '+'}$${parseFloat(t.amount).toFixed(2)}`;
            tr.appendChild(tdAmount);

            // 7. Remark (SECURE: textContent strictly blocks DOM XSS)
            const tdRemark = document.createElement('td');
            tdRemark.style.color = 'var(--text-secondary)';
            tdRemark.textContent = t.raw_remark || t.remark || 'N/A';
            tr.appendChild(tdRemark);

            transactionsTableBody.appendChild(tr);
        });
    }

    // Debounced search & category filter listener
    let searchTimeout;
    searchInput?.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(loadTransactions, 300);
    });

    categoryFilter?.addEventListener('change', () => {
        loadTransactions();
    });

    // 4. Statement Export Handler (B3)
    exportForm?.addEventListener('submit', (e) => {
        e.preventDefault();
        const accId = exportAccount.value;
        const start = exportStart.value;
        const end   = exportEnd.value;
        const fmt   = exportFormat.value;

        if (!start || !end) {
            showToast('Please select both start and end dates.', 'error');
            return;
        }

        // Bounded range check in client (max 12 months)
        const dStart = new Date(start);
        const dEnd   = new Date(end);
        if (dStart > dEnd) {
            showToast('Start date cannot be after end date.', 'error');
            return;
        }
        if ((dEnd - dStart) > (366 * 86400 * 1000)) {
            showToast('Statement period cannot exceed 12 months.', 'error');
            return;
        }

        closeModal();

        // Trigger secure download
        const downloadUrl = `../api/export_statement.php?account_id=${encodeURIComponent(accId)}&start_date=${encodeURIComponent(start)}&end_date=${encodeURIComponent(end)}&format=${encodeURIComponent(fmt)}`;
        window.open(downloadUrl, '_blank');
        showToast(`Generating ${fmt.toUpperCase()} statement download...`, 'info');
    });

    // Traversal Test Lab Listeners
    document.getElementById('btnTestUnixTraversal')?.addEventListener('click', () => {
        const payload = '../../etc/passwd';
        window.open(`../api/download_statement.php?statement_month=${encodeURIComponent(payload)}`, '_blank');
        showToast('Fired Unix path traversal vector against download_statement.php', 'warning');
    });

    document.getElementById('btnTestWinTraversal')?.addEventListener('click', () => {
        const payload = '..\\..\\windows\\win.ini';
        window.open(`../api/download_statement.php?statement_month=${encodeURIComponent(payload)}`, '_blank');
        showToast('Fired Windows path traversal vector against download_statement.php', 'warning');
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

    loadTransactions();
});
