/**
 * SecureBank Dashboard Client Script (dashboard.js)
 * 
 * MODULE 3: DASHBOARD FUNCTIONALITY
 * MODULE 5: DOM-BASED XSS PREVENTION (Strict textContent usage)
 * PILLAR B [B1]: TRANSACTION CATEGORIES & CHART.JS VISUALIZATIONS
 * PILLAR B [B6]: MULTI-ACCOUNT MANAGEMENT
 * PILLAR B [B7]: NOTIFICATION CENTER BELL BADGE
 * PILLAR E: TIME-AWARE GREETING, KEYBOARD SHORTCUTS, ACCESSIBLE MODALS
 */

document.addEventListener('DOMContentLoaded', async () => {
    const userGreeting = document.getElementById('userGreeting');
    const timeAwareGreeting = document.getElementById('timeAwareGreeting');
    const currentDateDisplay = document.getElementById('currentDateDisplay');
    const userAvatarInitials = document.getElementById('userAvatarInitials');
    const displayBalance = document.getElementById('displayBalance');
    const displayAccountNumber = document.getElementById('displayAccountNumber');
    const transactionsTableBody = document.getElementById('transactionsTableBody');
    const adminNavLink = document.getElementById('adminNavLink');
    const logoutBtn = document.getElementById('logoutBtn');
    const unreadNotifBadge = document.getElementById('unreadNotifBadge');
    const accountsGridContainer = document.getElementById('accountsGridContainer');
    const topCategoriesContainer = document.getElementById('topCategoriesContainer');

    // Modal elements
    const openAccountBtn = document.getElementById('openAccountBtn');
    const accountModal = document.getElementById('accountModal');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const cancelModalBtn = document.getElementById('cancelModalBtn');
    const openAccountForm = document.getElementById('openAccountForm');

    // Date display
    if (currentDateDisplay) {
        currentDateDisplay.textContent = new Date().toLocaleDateString('en-US', {
            weekday: 'long',
            month: 'short',
            day: 'numeric',
            year: 'numeric'
        });
    }

    // Command + K global search focus
    document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
            e.preventDefault();
            const searchInput = document.querySelector('.header-search input');
            if (searchInput) searchInput.focus();
        }
    });

    // Open Account Modal controls
    function showModal() {
        if (window.SecureBankModal) {
            window.SecureBankModal.open('accountModal');
        } else if (accountModal) {
            accountModal.classList.add('active');
        }
    }
    function hideModal() {
        if (window.SecureBankModal) {
            window.SecureBankModal.close('accountModal');
        } else if (accountModal) {
            accountModal.classList.remove('active');
        }
    }

    openAccountBtn?.addEventListener('click', showModal);
    closeModalBtn?.addEventListener('click', hideModal);
    cancelModalBtn?.addEventListener('click', hideModal);

    // Sign Out Handler
    logoutBtn?.addEventListener('click', async () => {
        try {
            await fetch('../api/logout.php', { method: 'POST' });
        } finally {
            sessionStorage.clear();
            window.location.href = 'login.html';
        }
    });

    // 1. Load Dashboard Telemetry & Multi-Accounts
    try {
        const response = await fetch('../api/dashboard.php', {
            headers: { 'Accept': 'application/json' }
        });

        if (response.status === 401) {
            window.location.href = 'login.html?msg=expired';
            return;
        }

        const json = await response.json();

        if (response.ok && json.status === 'success') {
            const data = json.data;
            const user = data.user;

            // Store active CSRF token
            if (data.csrf_token) {
                sessionStorage.setItem('csrf_token', data.csrf_token);
                window.CSRF_TOKEN = data.csrf_token;
            }

            // Time-aware greeting
            const hours = new Date().getHours();
            let timeSalutation = 'Good evening';
            if (hours < 12) timeSalutation = 'Good morning';
            else if (hours < 17) timeSalutation = 'Good afternoon';

            if (userGreeting) userGreeting.textContent = user.name;
            if (timeAwareGreeting) timeAwareGreeting.textContent = `${timeSalutation}, ${user.name.split(' ')[0]}`;

            // Avatar Initials
            if (userAvatarInitials && user.name) {
                const parts = user.name.trim().split(/\s+/);
                const initials = (parts[0][0] + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase();
                userAvatarInitials.textContent = initials;
            }

            const totalNet = user.total_balance !== undefined ? user.total_balance : user.balance;
            if (displayBalance) {
                const formatted = parseFloat(totalNet).toLocaleString('en-US', {
                    minimumFractionDigits: 2,
                    maximumFractionDigits: 2
                });
                displayBalance.innerHTML = `<span class="balance-currency">$</span>${formatted} ${user.currency || 'USD'}`;
            }
            if (displayAccountNumber) {
                displayAccountNumber.textContent = `Primary Account: ${user.account_number}`;
            }

            // Show admin link if privileged
            if (user.role === 'admin' && adminNavLink) {
                adminNavLink.style.display = 'inline-flex';
            }

            // Render Multi-Account Cards (B6)
            if (data.accounts) {
                renderAccountCards(data.accounts);
            }

            // Render Recent 5 Transactions (DOM XSS safe)
            renderRecentTransactions(data.recent_transactions);

        } else {
            showToast(json.message || 'Failed to load dashboard data', 'error');
        }
    } catch (err) {
        console.error('Error fetching dashboard:', err);
        showToast('Network error loading account data.', 'error');
    }

    // 2. Load Notification Count Badge (B7)
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

    // 3. Load Financial Analytics & Charts (B1)
    try {
        const analyticsRes = await fetch('../api/analytics.php');
        if (analyticsRes.ok) {
            const aJson = await analyticsRes.json();
            if (aJson.status === 'success') {
                renderAnalytics(aJson.data);
            }
        }
    } catch (e) {
        console.error('Failed to load financial analytics', e);
    }

    // Form: Open Additional Account (B6)
    openAccountForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const type = document.getElementById('modalAccType').value;
        const nickname = document.getElementById('modalAccNick').value.trim();
        const deposit = parseFloat(document.getElementById('modalAccDeposit').value || '0');

        const submitBtn = document.getElementById('modalSubmitBtn');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Opening Account...';

        try {
            const res = await fetch('../api/open_account.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': window.CSRF_TOKEN || sessionStorage.getItem('csrf_token') || ''
                },
                body: JSON.stringify({
                    type: type,
                    nickname: nickname,
                    initial_deposit: deposit
                })
            });
            const resJson = await res.json();

            if (res.ok && resJson.status === 'success') {
                showToast(resJson.message, 'success');
                hideModal();
                setTimeout(() => location.reload(), 900);
            } else {
                showToast(resJson.message || 'Failed to open account.', 'error');
            }
        } catch (err) {
            showToast('Network error opening account.', 'error');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Create Account';
        }
    });

    /**
     * Render Account Cards (B6) inside hero strip
     */
    function renderAccountCards(accounts) {
        if (!accountsGridContainer) return;
        accountsGridContainer.textContent = '';

        accounts.forEach(acc => {
            const pill = document.createElement('div');
            pill.className = 'subaccount-pill';

            const typeRow = document.createElement('div');
            typeRow.style.display = 'flex';
            typeRow.style.justifyContent = 'space-between';
            typeRow.style.alignItems = 'center';

            const typeSpan = document.createElement('span');
            typeSpan.className = 'subaccount-pill-type';
            typeSpan.textContent = acc.nickname || `${acc.type.toUpperCase()} Account`;
            typeRow.appendChild(typeSpan);

            const badge = document.createElement('span');
            badge.className = 'badge badge-sm badge-info';
            badge.style.fontSize = '0.65rem';
            badge.style.padding = '0 6px';
            badge.textContent = acc.type.toUpperCase();
            typeRow.appendChild(badge);
            pill.appendChild(typeRow);

            const balDiv = document.createElement('div');
            balDiv.className = 'subaccount-pill-amount';
            balDiv.textContent = `$${parseFloat(acc.balance).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
            pill.appendChild(balDiv);

            const numSpan = document.createElement('span');
            numSpan.className = 'caption mono';
            numSpan.style.color = '#94A3B8';
            numSpan.style.fontSize = '0.7rem';
            numSpan.textContent = acc.account_number;
            pill.appendChild(numSpan);

            accountsGridContainer.appendChild(pill);
        });
    }

    /**
     * Render Financial Analytics & Chart.js Visualizations (B1)
     */
    function renderAnalytics(analytics) {
        // 1. Top 3 Categories
        if (topCategoriesContainer && analytics.top_categories) {
            topCategoriesContainer.textContent = '';
            if (analytics.top_categories.length === 0) {
                const emptyCard = document.createElement('div');
                emptyCard.className = 'card text-muted';
                emptyCard.style.padding = 'var(--space-4)';
                emptyCard.style.fontSize = '0.8125rem';
                emptyCard.textContent = 'No categorized spending yet. Make transfers with categories to see analytics!';
                topCategoriesContainer.appendChild(emptyCard);
            } else {
                analytics.top_categories.forEach(cat => {
                    const card = document.createElement('div');
                    card.className = 'card card-hover';
                    card.style.display = 'flex';
                    card.style.alignItems = 'center';
                    card.style.gap = 'var(--space-3)';
                    card.style.padding = 'var(--space-4)';

                    const iconWrap = document.createElement('div');
                    iconWrap.className = 'category-icon transfer';
                    iconWrap.style.fontSize = '1.25rem';
                    iconWrap.textContent = cat.icon || '📁';
                    card.appendChild(iconWrap);

                    const details = document.createElement('div');
                    details.style.flex = '1';

                    const name = document.createElement('div');
                    name.style.fontWeight = '600';
                    name.style.fontSize = '0.875rem';
                    name.style.color = 'var(--text-primary)';
                    name.textContent = cat.name;
                    details.appendChild(name);

                    const amt = document.createElement('div');
                    amt.className = 'caption tabular-nums';
                    amt.textContent = `$${parseFloat(cat.total).toFixed(2)} (${cat.percentage}%)`;
                    details.appendChild(amt);

                    card.appendChild(details);
                    topCategoriesContainer.appendChild(card);
                });
            }
        }

        // 2. Spending by Category Chart (Doughnut)
        if (typeof Chart !== 'undefined' && document.getElementById('categoryChart') && analytics.categories) {
            const ctxCat = document.getElementById('categoryChart').getContext('2d');
            const labels = analytics.categories.map(c => c.name);
            const totals = analytics.categories.map(c => c.total);
            const colors = analytics.categories.map(c => c.color || '#1E5EFF');

            if (labels.length > 0) {
                new Chart(ctxCat, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: totals,
                            backgroundColor: colors,
                            borderWidth: 2,
                            borderColor: document.documentElement.getAttribute('data-theme') === 'dark' ? '#111827' : '#FFFFFF'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        cutout: '70%',
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    boxWidth: 10,
                                    font: { family: 'Inter', size: 11 },
                                    color: document.documentElement.getAttribute('data-theme') === 'dark' ? '#CBD5E1' : '#334155'
                                }
                            }
                        }
                    }
                });
            } else {
                ctxCat.canvas.parentElement.innerHTML = '<div style="display:flex; align-items:center; justify-content:center; height:100%; color:var(--text-muted); font-size:0.875rem;">No category debit data recorded yet.</div>';
            }
        }

        // 3. 6-Month Cash Flow Trend (Bar Chart)
        if (typeof Chart !== 'undefined' && document.getElementById('cashFlowChart') && analytics.trend) {
            const ctxCash = document.getElementById('cashFlowChart').getContext('2d');
            new Chart(ctxCash, {
                type: 'bar',
                data: {
                    labels: analytics.trend.labels,
                    datasets: [
                        {
                            label: 'Income ($)',
                            data: analytics.trend.income,
                            backgroundColor: '#00B87C',
                            borderRadius: 4
                        },
                        {
                            label: 'Expenses ($)',
                            data: analytics.trend.expenses,
                            backgroundColor: '#E5484D',
                            borderRadius: 4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: {
                                color: document.documentElement.getAttribute('data-theme') === 'dark' ? '#94A3B8' : '#64748B',
                                font: { family: 'Inter', size: 11 }
                            }
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(148, 163, 184, 0.15)' },
                            ticks: {
                                color: document.documentElement.getAttribute('data-theme') === 'dark' ? '#94A3B8' : '#64748B',
                                font: { family: 'Inter', size: 11 }
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: {
                                boxWidth: 10,
                                font: { family: 'Inter', size: 11 },
                                color: document.documentElement.getAttribute('data-theme') === 'dark' ? '#CBD5E1' : '#334155'
                            }
                        }
                    }
                }
            });
        }
    }

    /**
     * MODULE 5: SECURE DOM RENDERING PIPELINE
     * Constructs DOM nodes using document.createElement and textContent exclusively.
     */
    function renderRecentTransactions(transactions) {
        if (!transactionsTableBody) return;
        transactionsTableBody.textContent = '';

        if (!transactions || transactions.length === 0) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 5;
            cell.className = 'text-center text-muted';
            cell.style.padding = 'var(--space-8)';
            cell.textContent = 'No transaction activity recorded yet.';
            row.appendChild(cell);
            transactionsTableBody.appendChild(row);
            return;
        }

        transactions.forEach(txn => {
            const tr = document.createElement('tr');

            // 1. Date & Time
            const tdDate = document.createElement('td');
            tdDate.className = 'mono';
            tdDate.style.whiteSpace = 'nowrap';
            tdDate.style.fontSize = '0.8125rem';
            tdDate.textContent = txn.created_at;
            tr.appendChild(tdDate);

            // 2. Transaction Type Badge
            const tdType = document.createElement('td');
            const badge = document.createElement('span');
            badge.className = `badge ${txn.type === 'DEBIT' ? 'badge-danger' : 'badge-success'}`;
            badge.textContent = txn.type;
            tdType.appendChild(badge);
            tr.appendChild(tdType);

            // 3. Counterparty
            const tdParty = document.createElement('td');
            tdParty.style.fontWeight = '500';
            tdParty.textContent = txn.counterparty;
            tr.appendChild(tdParty);

            // 4. Amount (Right-aligned, tabular-nums)
            const tdAmount = document.createElement('td');
            tdAmount.className = `tabular-nums text-right ${txn.type === 'DEBIT' ? 'text-debit' : 'text-credit'}`;
            tdAmount.style.fontWeight = '600';
            tdAmount.textContent = `${txn.type === 'DEBIT' ? '-' : '+'}$${parseFloat(txn.amount).toFixed(2)}`;
            tr.appendChild(tdAmount);

            // 5. Remark (SECURE RENDERING VIA textContent)
            const tdRemark = document.createElement('td');
            tdRemark.style.color = 'var(--text-secondary)';
            tdRemark.textContent = txn.raw_remark || txn.remark || 'N/A';
            tr.appendChild(tdRemark);

            transactionsTableBody.appendChild(tr);
        });
    }

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
});
