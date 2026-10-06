/**
 * SecureBank Trusted Devices & Sessions Client Script (devices.js)
 * 
 * PILLAR B [B8]: PRIVACY-PRESERVING DEVICE FINGERPRINTING & SESSION REVOCATION
 * PILLAR E: SVG DEVICE ICONS, FINTECH CARD STYLING, ZERO INLINE SCRIPTS
 */

document.addEventListener('DOMContentLoaded', async () => {
    let csrfToken = '';
    const container = document.getElementById('deviceListContainer');
    const badge = document.getElementById('deviceCountBadge');
    const logoutBtn = document.getElementById('logoutBtn');

    // Sign Out Handler
    logoutBtn?.addEventListener('click', async () => {
        try {
            await fetch('../api/logout.php', { method: 'POST' });
        } finally {
            sessionStorage.clear();
            window.location.href = 'login.html';
        }
    });

    try {
        const dashRes = await fetch('../api/dashboard.php');
        if (dashRes.status === 401) { window.location.href = 'login.html?msg=expired'; return; }
        const dashData = await dashRes.json();
        csrfToken = dashData.data?.csrf_token || sessionStorage.getItem('csrf_token') || '';
    } catch (e) {
        console.error('CSRF fetch error', e);
    }

    async function loadDevices() {
        try {
            const res = await fetch('../api/devices.php');
            if (res.status === 401) { window.location.href = 'login.html?msg=expired'; return; }
            const json = await res.json();

            if (json.status === 'success') {
                renderDevices(json.data);
            }
        } catch (e) {
            console.error('Error loading devices', e);
        }
    }

    function renderDevices(devices) {
        if (!container) return;
        if (badge) badge.textContent = `${devices.length} Registered`;
        container.textContent = '';

        if (!devices || devices.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'card text-muted';
            empty.style.textAlign = 'center';
            empty.style.padding = 'var(--space-8)';
            empty.textContent = 'No trusted devices recorded yet.';
            container.appendChild(empty);
            return;
        }

        devices.forEach(d => {
            const card = document.createElement('div');
            card.className = `card ${d.is_current_device ? 'card-hover' : ''}`;
            card.style.display = 'flex';
            card.style.alignItems = 'center';
            card.style.justifyContent = 'space-between';
            card.style.marginBottom = 'var(--space-3)';
            card.style.borderLeft = d.is_current_device ? '4px solid var(--color-secondary)' : '1px solid var(--border-subtle)';

            const leftSide = document.createElement('div');
            leftSide.style.display = 'flex';
            leftSide.style.alignItems = 'center';
            leftSide.style.gap = 'var(--space-4)';

            const iconDiv = document.createElement('div');
            iconDiv.style.width = '42px';
            iconDiv.style.height = '42px';
            iconDiv.style.borderRadius = 'var(--radius-md)';
            iconDiv.style.backgroundColor = d.is_current_device ? 'var(--color-secondary-subtle)' : 'var(--bg-subtle)';
            iconDiv.style.color = d.is_current_device ? 'var(--color-secondary)' : 'var(--text-muted)';
            iconDiv.style.display = 'flex';
            iconDiv.style.alignItems = 'center';
            iconDiv.style.justifyContent = 'center';
            iconDiv.style.flexShrink = '0';

            const isDesktop = d.platform.includes('Mac') || d.platform.includes('Windows') || d.platform.includes('Linux');
            iconDiv.innerHTML = isDesktop
                ? '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>'
                : '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>';
            leftSide.appendChild(iconDiv);

            const infoDiv = document.createElement('div');

            const titleRow = document.createElement('div');
            titleRow.style.display = 'flex';
            titleRow.style.alignItems = 'center';
            titleRow.style.gap = 'var(--space-2)';

            const strong = document.createElement('strong');
            strong.style.color = 'var(--text-primary)';
            strong.style.fontSize = '0.95rem';
            strong.textContent = `${d.platform} • ${d.browser}`;
            titleRow.appendChild(strong);

            if (d.is_current_device) {
                const curBadge = document.createElement('span');
                curBadge.className = 'badge badge-success';
                curBadge.textContent = 'This Device (Active)';
                titleRow.appendChild(curBadge);
            }

            if (d.is_revoked) {
                const revBadge = document.createElement('span');
                revBadge.className = 'badge badge-danger';
                revBadge.textContent = 'Revoked';
                titleRow.appendChild(revBadge);
            }

            infoDiv.appendChild(titleRow);

            const sub = document.createElement('div');
            sub.className = 'caption mono';
            sub.style.marginTop = '4px';
            sub.style.color = 'var(--text-muted)';
            sub.textContent = `IP: ${d.ip_address} | Last Active: ${d.last_login_at}`;
            infoDiv.appendChild(sub);

            leftSide.appendChild(infoDiv);
            card.appendChild(leftSide);

            if (!d.is_revoked) {
                const revokeBtn = document.createElement('button');
                revokeBtn.type = 'button';
                revokeBtn.className = 'btn btn-danger btn-sm';
                revokeBtn.textContent = 'Revoke Access';
                revokeBtn.addEventListener('click', async () => {
                    if (confirm('Revoke access for this device? This will invalidate its active session token.')) {
                        await revokeDevice(d.id);
                    }
                });
                card.appendChild(revokeBtn);
            }

            container.appendChild(card);
        });
    }

    async function revokeDevice(id) {
        try {
            const res = await fetch('../api/device_revoke.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ device_id: id })
            });
            const data = await res.json();

            if (res.ok && data.status === 'success') {
                if (data.logged_out) {
                    showToast('Current session revoked. Redirecting to login...', 'warning');
                    setTimeout(() => window.location.href = data.redirect || 'login.html', 1000);
                    return;
                }
                showToast(data.message, 'success');
                loadDevices();
            } else {
                showToast(data.message || 'Failed to revoke device.', 'error');
            }
        } catch (e) {
            showToast('Network error revoking device.', 'error');
        }
    }

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

    loadDevices();
});
