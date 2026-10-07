/**
 * SecureBank SOC SIEM Dashboard Client Logic (admin_soc.js)
 * Pillar C: Real-Time Observability & SIEM Incident Triage
 */

document.addEventListener('DOMContentLoaded', () => {
    const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

    // Export Modal Controls
    const exportModal = document.getElementById('exportModal');
    const openExportModalBtn = document.getElementById('openExportModalBtn');
    const closeExportModalBtn = document.getElementById('closeExportModalBtn');

    if (openExportModalBtn && exportModal) {
        openExportModalBtn.addEventListener('click', () => {
            exportModal.style.display = 'flex';
        });
    }

    if (closeExportModalBtn && exportModal) {
        closeExportModalBtn.addEventListener('click', () => {
            exportModal.style.display = 'none';
        });
    }

    window.addEventListener('click', (e) => {
        if (exportModal && e.target === exportModal) {
            exportModal.style.display = 'none';
        }
    });

    // Acknowledge Alert Handler
    document.addEventListener('click', async (e) => {
        const btn = e.target.closest('.btn-ack-alert');
        if (btn) {
            const alertId = btn.getAttribute('data-id');
            btn.disabled = true;
            btn.textContent = 'Processing...';

            try {
                const res = await fetch('acknowledge_alert.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': CSRF_TOKEN
                    },
                    body: JSON.stringify({ alert_id: alertId })
                });
                const json = await res.json();
                if (json.status === 'success') {
                    btn.outerHTML = '<span style="font-size:0.75rem; color:#1E5EFF; font-weight:600;">✓ Acknowledged</span>';
                    if (window.showToast) window.showToast('Incident acknowledged.', 'success');
                } else {
                    alert(json.message || 'Failed to acknowledge alert.');
                    btn.disabled = false;
                    btn.textContent = 'Acknowledge';
                }
            } catch (err) {
                alert('Network error acknowledging alert.');
                btn.disabled = false;
                btn.textContent = 'Acknowledge';
            }
        }
    });

    // Admin Sign Out
    document.getElementById('logoutBtn')?.addEventListener('click', async () => {
        try {
            await fetch('../api/logout.php', { method: 'POST' });
        } finally {
            window.location.href = '../frontend/login.html';
        }
    });

    // 10-Second Telemetry Polling Routine for Non-SSE Panels
    async function refreshDashboardPanels() {
        try {
            const res = await fetch('security-dashboard.php?action=fetch_telemetry');
            if (!res.ok) return;
            const data = await res.json();
            if (data.status === 'success') {
                // Update Metric Counters
                const m = data.metrics;
                const totalLoginsEl = document.getElementById('valTotalLogins');
                const failedLoginsEl = document.getElementById('valFailedLogins');
                const blockedThreatsEl = document.getElementById('valBlockedThreats');
                const activeSessionsEl = document.getElementById('valActiveSessions');

                if (totalLoginsEl) totalLoginsEl.textContent = m.total_logins;
                if (failedLoginsEl) failedLoginsEl.textContent = m.failed_logins;
                if (blockedThreatsEl) {
                    blockedThreatsEl.textContent = (
                        parseInt(m.blocked_sqli || 0) + parseInt(m.blocked_xss || 0) +
                        parseInt(m.blocked_csrf || 0) + parseInt(m.blocked_traversal || 0) +
                        parseInt(m.blocked_ssrf || 0)
                    );
                }
                if (activeSessionsEl) activeSessionsEl.textContent = m.active_sessions;

                // Update Severities
                if (m.severity) {
                    const critEl = document.getElementById('cntSevCritical');
                    const highEl = document.getElementById('cntSevHigh');
                    const medEl = document.getElementById('cntSevMedium');
                    const lowEl = document.getElementById('cntSevLow');

                    if (critEl) critEl.textContent = m.severity.critical || 0;
                    if (highEl) highEl.textContent = m.severity.high || 0;
                    if (medEl) medEl.textContent = m.severity.medium || 0;
                    if (lowEl) lowEl.textContent = m.severity.low || 0;
                }

                // Update Active Alerts badge
                const badge = document.getElementById('activeAlertsBadge');
                if (badge) {
                    if (data.unack_alerts > 0) {
                        badge.className = 'alert-pill-badge';
                        badge.style.background = '';
                        badge.textContent = `${data.unack_alerts} ACTIVE ALERTS`;
                    } else {
                        badge.className = 'status-badge status-live';
                        badge.style.background = '';
                        badge.textContent = '0 ALERTS';
                    }
                }

                // Update Active Alerts Container
                const alertsContainer = document.getElementById('alertsPanelContainer');
                if (alertsContainer && Array.isArray(data.alerts)) {
                    alertsContainer.textContent = '';
                    if (data.alerts.length === 0) {
                        const p = document.createElement('p');
                        p.style.color = '#64748B';
                        p.style.fontSize = '0.85rem';
                        p.textContent = 'No active alert incidents logged.';
                        alertsContainer.appendChild(p);
                    } else {
                        data.alerts.forEach(a => {
                            const row = document.createElement('div');
                            row.style.cssText = 'border-bottom: 1px solid #E2E8F0; padding: 0.5rem 0; display: flex; justify-content: space-between; align-items: center;';

                            const leftDiv = document.createElement('div');
                            const topDiv = document.createElement('div');
                            topDiv.style.cssText = 'display: flex; gap: 0.5rem; align-items: center;';

                            const nameStrong = document.createElement('strong');
                            nameStrong.style.cssText = 'font-size: 0.85rem; color: #0F172A;';
                            nameStrong.textContent = a.rule_name;

                            const pill = document.createElement('span');
                            pill.className = `severity-pill pill-${a.severity}`;
                            pill.textContent = (a.severity || 'low').toUpperCase();

                            topDiv.appendChild(nameStrong);
                            topDiv.appendChild(pill);

                            const timeDiv = document.createElement('div');
                            timeDiv.style.cssText = 'font-size: 0.75rem; color: #64748B; margin-top: 2px;';
                            timeDiv.textContent = a.triggered_at;

                            leftDiv.appendChild(topDiv);
                            leftDiv.appendChild(timeDiv);

                            const rightDiv = document.createElement('div');
                            if (a.acknowledged == 1) {
                                const ackSpan = document.createElement('span');
                                ackSpan.style.cssText = 'font-size: 0.75rem; color: #1E5EFF; font-weight: 600;';
                                ackSpan.textContent = '✓ Acknowledged';
                                rightDiv.appendChild(ackSpan);
                            } else {
                                const ackBtn = document.createElement('button');
                                ackBtn.className = 'btn btn-outline btn-sm btn-ack-alert';
                                ackBtn.setAttribute('data-id', a.id);
                                ackBtn.style.padding = '2px 8px';
                                ackBtn.style.fontSize = '0.75rem';
                                ackBtn.textContent = 'Acknowledge';
                                rightDiv.appendChild(ackBtn);
                            }

                            row.appendChild(leftDiv);
                            row.appendChild(rightDiv);
                            alertsContainer.appendChild(row);
                        });
                    }
                }

                // Update timestamp
                const tsEl = document.getElementById('lastPolledTimestamp');
                if (tsEl) tsEl.textContent = `Panels updated at ${data.time}`;
            }
        } catch (err) {
            console.warn('Dashboard panel polling error:', err);
        }
    }

    setInterval(refreshDashboardPanels, 10000);
});
