/**
 * SecureBank Recurring & Scheduled Transfers Script (schedule.js)
 * 
 * PILLAR B [B2]: ZERO-CRON RECURRING TRANSFERS & AUTOMATED FAILURE-PAUSE
 * PILLAR E: FINTECH TWO-COLUMN FORM & TABLE, ZERO INLINE SCRIPTS
 */

document.addEventListener('DOMContentLoaded', async () => {
    let csrfToken = '';
    const logoutBtn = document.getElementById('logoutBtn');
    const form = document.getElementById('scheduleForm');
    const submitBtn = document.getElementById('submitSchedBtn');
    const schedCountBadge = document.getElementById('schedCountBadge');
    const tbody = document.getElementById('schedulesTableBody');

    // Sign Out Handler
    logoutBtn?.addEventListener('click', async () => {
        try {
            await fetch('../api/logout.php', { method: 'POST' });
        } finally {
            sessionStorage.clear();
            window.location.href = 'login.html';
        }
    });

    // Default start date = tomorrow
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const startInput = document.getElementById('schedStartDate');
    if (startInput) startInput.value = tomorrow.toISOString().split('T')[0];

    // 1. Fetch Dashboard & User Accounts
    try {
        const dashRes = await fetch('../api/dashboard.php');
        if (dashRes.status === 401) { window.location.href = 'login.html?msg=expired'; return; }
        const dashJson = await dashRes.json();
        csrfToken = dashJson.data?.csrf_token || sessionStorage.getItem('csrf_token') || '';

        const accSelect = document.getElementById('fromAccount');
        if (accSelect) {
            accSelect.textContent = '';
            (dashJson.data?.accounts || []).forEach(acc => {
                const opt = document.createElement('option');
                opt.value = acc.id;
                opt.textContent = `${acc.nickname || acc.type.toUpperCase()} (${acc.account_number}) - $${parseFloat(acc.balance).toFixed(2)}`;
                accSelect.appendChild(opt);
            });
        }
    } catch (e) {
        console.error('Failed to load accounts', e);
    }

    // 2. Fetch Beneficiaries (Only Verified ones can be selected)
    try {
        const benRes = await fetch('../api/beneficiaries.php');
        const benJson = await benRes.json();
        const benSelect = document.getElementById('toBeneficiary');
        if (benSelect) {
            benSelect.textContent = '';
            let verifiedCount = 0;
            (benJson.data || []).forEach(b => {
                if (b.verified) {
                    verifiedCount++;
                    const opt = document.createElement('option');
                    opt.value = b.id;
                    opt.textContent = `${b.name} (${b.account_number})`;
                    benSelect.appendChild(opt);
                }
            });

            if (verifiedCount === 0) {
                const opt = document.createElement('option');
                opt.value = '';
                opt.textContent = '-- No verified payees found. Please verify a beneficiary first --';
                benSelect.appendChild(opt);
            }
        }
    } catch (e) {
        console.error('Failed to load beneficiaries', e);
    }

    // 3. Load Scheduled Transfers List
    async function loadSchedules() {
        try {
            const res = await fetch('../api/scheduled_list.php');
            if (res.status === 401) { window.location.href = 'login.html?msg=expired'; return; }
            const json = await res.json();
            if (json.status === 'success') {
                renderSchedules(json.data);
            }
        } catch (e) {
            console.error('Failed to load scheduled transfers', e);
        }
    }

    function renderSchedules(list) {
        if (!tbody) return;
        if (schedCountBadge) schedCountBadge.textContent = `${list.length} Schedules`;
        tbody.textContent = '';

        if (!list || list.length === 0) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 5;
            td.className = 'text-center text-muted';
            td.style.padding = 'var(--space-8)';
            td.textContent = 'No recurring transfers configured yet.';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }

        list.forEach(item => {
            const tr = document.createElement('tr');

            const tdPayee = document.createElement('td');
            const payeeName = document.createElement('strong');
            payeeName.style.fontSize = '0.9rem';
            payeeName.style.color = 'var(--text-primary)';
            payeeName.textContent = item.payee_name;
            tdPayee.appendChild(payeeName);

            const payeeAcc = document.createElement('div');
            payeeAcc.className = 'caption mono';
            payeeAcc.style.color = 'var(--text-muted)';
            payeeAcc.textContent = item.payee_account;
            tdPayee.appendChild(payeeAcc);
            tr.appendChild(tdPayee);

            const tdAmt = document.createElement('td');
            tdAmt.className = 'tabular-nums';
            const amtStrong = document.createElement('strong');
            amtStrong.textContent = `$${parseFloat(item.amount).toFixed(2)}`;
            tdAmt.appendChild(amtStrong);

            const freqBadge = document.createElement('div');
            freqBadge.className = 'caption';
            freqBadge.style.color = 'var(--color-secondary)';
            freqBadge.style.fontWeight = '600';
            freqBadge.textContent = item.frequency.toUpperCase();
            tdAmt.appendChild(freqBadge);
            tr.appendChild(tdAmt);

            const tdNext = document.createElement('td');
            tdNext.className = 'mono';
            tdNext.style.fontSize = '0.8125rem';
            tdNext.textContent = item.next_run_at ? item.next_run_at.substring(0, 10) : 'N/A';
            tr.appendChild(tdNext);

            const tdStatus = document.createElement('td');
            const sBadge = document.createElement('span');
            sBadge.className = `badge ${item.status === 'active' ? 'badge-success' : (item.status === 'paused' ? 'badge-warning' : 'badge-neutral')}`;
            sBadge.textContent = item.status.toUpperCase();
            tdStatus.appendChild(sBadge);
            tr.appendChild(tdStatus);

            const tdAction = document.createElement('td');
            if (item.status === 'active') {
                const pBtn = document.createElement('button');
                pBtn.type = 'button';
                pBtn.className = 'btn btn-secondary btn-sm';
                pBtn.style.padding = '4px 8px';
                pBtn.style.fontSize = '0.75rem';
                pBtn.textContent = '⏸ Pause';
                pBtn.addEventListener('click', () => toggleStatus(item.id, 'pause'));
                tdAction.appendChild(pBtn);
            } else if (item.status === 'paused') {
                const rBtn = document.createElement('button');
                rBtn.type = 'button';
                rBtn.className = 'btn btn-primary btn-sm';
                rBtn.style.padding = '4px 8px';
                rBtn.style.fontSize = '0.75rem';
                rBtn.textContent = '▶ Resume';
                rBtn.addEventListener('click', () => toggleStatus(item.id, 'resume'));
                tdAction.appendChild(rBtn);
            }
            tr.appendChild(tdAction);

            tbody.appendChild(tr);
        });
    }

    async function toggleStatus(id, action) {
        try {
            const res = await fetch('../api/scheduled_pause.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ id: id, action: action })
            });
            const data = await res.json();
            if (res.ok && data.status === 'success') {
                showToast(data.message, 'success');
                loadSchedules();
            } else {
                showToast(data.message || 'Action failed.', 'error');
            }
        } catch (e) {
            showToast('Network error updating schedule.', 'error');
        }
    }

    // Schedule Submit Handler
    form?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const fromAcc = document.getElementById('fromAccount').value;
        const toBen   = document.getElementById('toBeneficiary').value;
        const amount  = parseFloat(document.getElementById('schedAmount').value || '0');
        const freq    = document.getElementById('schedFrequency').value;
        const cat     = document.getElementById('schedCategory').value;
        const start   = document.getElementById('schedStartDate').value;
        const remark  = document.getElementById('schedRemark').value;

        if (!toBen) {
            showToast('Please select a verified payee.', 'error');
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = 'Scheduling...';

        try {
            const res = await fetch('../api/schedule_transfer.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    from_account_id: parseInt(fromAcc, 10),
                    to_beneficiary_id: parseInt(toBen, 10),
                    amount: amount,
                    frequency: freq,
                    category: cat,
                    start_date: start,
                    remark: remark
                })
            });
            const data = await res.json();

            if (res.ok && data.status === 'success') {
                showToast(data.message, 'success');
                form.reset();
                loadSchedules();
            } else {
                showToast(data.message || 'Failed to schedule transfer.', 'error');
            }
        } catch (err) {
            showToast('Network error creating recurring transfer.', 'error');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Schedule Recurring Transfer';
        }
    });

    function showToast(msg, type = 'info') {
        if (window.showToast) {
            window.showToast(msg, type);
            return;
        }
        const c = document.getElementById('toastContainer');
        if (!c) return;
        const t = document.createElement('div');
        t.className = `toast toast-${type}`;
        t.textContent = msg;
        c.appendChild(t);
        setTimeout(() => { t.classList.add('toast-fade'); setTimeout(() => t.remove(), 300); }, 3000);
    }

    loadSchedules();
});
