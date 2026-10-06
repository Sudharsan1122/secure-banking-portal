/**
 * SecureBank Notification Center Client Script (notifications.js)
 * 
 * PILLAR B [B7]: NOTIFICATION CENTER & TENANT-ISOLATED ALERTS
 * PILLAR E: FINTECH ALERT STYLING, SVG ICONS, STRICT CSP NONCE COMPLIANCE
 */

document.addEventListener('DOMContentLoaded', async () => {
    let csrfToken = '';
    const container = document.getElementById('notificationsList');
    const badge = document.getElementById('unreadCountBadge');
    const markAllBtn = document.getElementById('markAllReadBtn');
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

    async function loadNotifications() {
        try {
            const res = await fetch('../api/notifications.php');
            if (res.status === 401) { window.location.href = 'login.html?msg=expired'; return; }
            const json = await res.json();

            if (json.status === 'success') {
                renderList(json.data, json.unread_count);
            }
        } catch (e) {
            console.error('Failed to load notifications', e);
        }
    }

    function renderList(items, unreadCount) {
        if (!container) return;
        if (badge) {
            badge.textContent = `${unreadCount} Unread`;
            badge.className = unreadCount > 0 ? 'badge badge-warning' : 'badge badge-success';
        }

        container.textContent = '';

        if (!items || items.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'text-muted';
            empty.style.padding = 'var(--space-8)';
            empty.style.textAlign = 'center';
            empty.textContent = 'No notification activity on record.';
            container.appendChild(empty);
            return;
        }

        items.forEach(n => {
            const item = document.createElement('div');
            item.className = 'card';
            item.style.display = 'flex';
            item.style.alignItems = 'flex-start';
            item.style.gap = 'var(--space-4)';
            item.style.padding = 'var(--space-4)';
            item.style.marginBottom = 'var(--space-3)';
            item.style.borderRadius = 'var(--radius-md)';
            if (!n.is_read) {
                item.style.borderLeft = '4px solid var(--color-secondary)';
                item.style.backgroundColor = 'var(--color-secondary-subtle)';
            }

            // Severity SVG Icon Box
            const iconBox = document.createElement('div');
            iconBox.style.width = '38px';
            iconBox.style.height = '38px';
            iconBox.style.borderRadius = 'var(--radius-md)';
            iconBox.style.display = 'flex';
            iconBox.style.alignItems = 'center';
            iconBox.style.justifyContent = 'center';
            iconBox.style.flexShrink = '0';

            if (n.severity === 'danger') {
                iconBox.style.backgroundColor = 'var(--color-danger-bg)';
                iconBox.style.color = 'var(--color-danger)';
                iconBox.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
            } else if (n.severity === 'warning') {
                iconBox.style.backgroundColor = 'var(--color-warning-bg)';
                iconBox.style.color = 'var(--color-warning)';
                iconBox.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
            } else {
                iconBox.style.backgroundColor = 'var(--color-info-bg)';
                iconBox.style.color = 'var(--color-info)';
                iconBox.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>';
            }
            item.appendChild(iconBox);

            // Content
            const content = document.createElement('div');
            content.style.flex = '1';

            const headerRow = document.createElement('div');
            headerRow.style.display = 'flex';
            headerRow.style.justifyContent = 'space-between';
            headerRow.style.alignItems = 'center';
            headerRow.style.marginBottom = '2px';

            const title = document.createElement('strong');
            title.style.fontSize = '0.95rem';
            title.style.color = 'var(--text-primary)';
            title.textContent = n.title;
            headerRow.appendChild(title);

            const time = document.createElement('span');
            time.className = 'caption mono';
            time.style.color = 'var(--text-muted)';
            time.textContent = n.created_at;
            headerRow.appendChild(time);
            content.appendChild(headerRow);

            const body = document.createElement('p');
            body.className = 'body';
            body.style.fontSize = '0.8125rem';
            body.style.margin = '2px 0 8px 0';
            body.style.color = 'var(--text-secondary)';
            body.textContent = n.body;
            content.appendChild(body);

            if (n.link) {
                const link = document.createElement('a');
                link.href = n.link;
                link.className = 'btn btn-secondary btn-sm';
                link.style.fontSize = '0.75rem';
                link.textContent = 'View Activity →';
                content.appendChild(link);
            }

            item.appendChild(content);

            // Mark single as read button
            if (!n.is_read) {
                const markBtn = document.createElement('button');
                markBtn.type = 'button';
                markBtn.className = 'btn btn-ghost btn-sm';
                markBtn.style.fontSize = '0.75rem';
                markBtn.textContent = '✓ Mark Read';
                markBtn.addEventListener('click', async () => {
                    await markRead(n.id);
                });
                item.appendChild(markBtn);
            }

            container.appendChild(item);
        });
    }

    async function markRead(id) {
        try {
            const res = await fetch('../api/mark_read.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ id: id })
            });
            const data = await res.json();
            if (res.ok && data.status === 'success') {
                loadNotifications();
            }
        } catch (e) {
            console.error('Mark read error', e);
        }
    }

    markAllBtn?.addEventListener('click', async () => {
        await markRead('all');
    });

    loadNotifications();
});
