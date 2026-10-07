/**
 * SOC Live Real-Time Security Event Feed (EventSource / SSE Client)
 * 
 * PILLAR C [C1]: REAL-TIME SECURITY FEED (SSE)
 * PILLAR C [C2]: SEVERITY-COLORED TELEMETRY & DOM XSS PREVENTATIVE RENDERING
 * 
 * WHY SSE OVER WEBSOCKETS / POLLING:
 * SSE operates over standard HTTP/HTTPS, auto-reconnects natively via browser standard,
 * works through enterprise firewalls, and consumes zero connection threads when idle.
 * Fallback to 10-second polling ensures uninterrupted telemetry if SSE is blocked.
 * 
 * DOM XSS MITIGATION:
 * All dynamic fields (event_type, ip_address, username, details) are assigned strictly
 * using Node.textContent and document.createElement, never element.innerHTML.
 */

(function () {
    'use strict';

    let eventSource = null;
    let failureCount = 0;
    const MAX_FAILURES_BEFORE_POLL = 3;
    let isPollingFallback = false;
    let pollInterval = null;
    let lastEventId = 0;

    const statusBadge = document.getElementById('sse-status-badge');
    const feedContainer = document.getElementById('soc-feed-container');
    const feedCountBadge = document.getElementById('feed-count-badge');
    const severityFilter = document.getElementById('severity-filter');

    // Severity color mapping
    const SEVERITY_CLASSES = {
        low: 'severity-low',
        medium: 'severity-medium',
        high: 'severity-high',
        critical: 'severity-critical'
    };

    /**
     * Update connection status badge
     */
    function updateStatus(status) {
        if (!statusBadge) return;
        statusBadge.className = 'status-badge';
        if (status === 'LIVE') {
            statusBadge.classList.add('status-live');
            statusBadge.textContent = '● LIVE (SSE)';
        } else if (status === 'RECONNECTING') {
            statusBadge.classList.add('status-reconnecting');
            statusBadge.textContent = '◌ RECONNECTING...';
        } else if (status === 'POLLING') {
            statusBadge.classList.add('status-polling');
            statusBadge.textContent = '⟳ FALLBACK (POLL 10s)';
        } else {
            statusBadge.classList.add('status-offline');
            statusBadge.textContent = '✕ OFFLINE';
        }
    }

    /**
     * Render a single security event into the feed DOM using strict textContent sinks
     */
    function appendEventToFeed(eventData) {
        if (!feedContainer) return;

        // Skip if severity filter is active and does not match
        if (severityFilter && severityFilter.value !== 'all' && eventData.severity !== severityFilter.value) {
            return;
        }

        // Avoid duplicate event insertions
        if (document.getElementById(`event-row-${eventData.id}`)) {
            return;
        }

        // Remove initial connecting placeholder once real events begin rendering
        const placeholder = feedContainer.querySelector('p');
        if (placeholder) {
            placeholder.remove();
        }

        const row = document.createElement('div');
        row.id = `event-row-${eventData.id}`;
        row.className = `feed-event-row ${SEVERITY_CLASSES[eventData.severity] || 'severity-low'}`;
        row.setAttribute('data-severity', eventData.severity);

        // Header: Timestamp + Event Type + Severity Pill
        const headerDiv = document.createElement('div');
        headerDiv.className = 'event-header';

        const timeSpan = document.createElement('span');
        timeSpan.className = 'event-time';
        timeSpan.textContent = eventData.timestamp;

        const typeSpan = document.createElement('span');
        typeSpan.className = 'event-type';
        typeSpan.textContent = eventData.event_type;

        const sevPill = document.createElement('span');
        sevPill.className = `severity-pill pill-${eventData.severity}`;
        sevPill.textContent = (eventData.severity || 'low').toUpperCase();

        headerDiv.appendChild(timeSpan);
        headerDiv.appendChild(typeSpan);
        headerDiv.appendChild(sevPill);

        // Details Row: IP + User + Status + Payload Summary
        const bodyDiv = document.createElement('div');
        bodyDiv.className = 'event-body';

        const metaSpan = document.createElement('span');
        metaSpan.className = 'event-meta';
        metaSpan.textContent = `[IP: ${eventData.ip_address}] [User: ${eventData.username || 'System'}] [Status: ${eventData.status}]`;

        const descSpan = document.createElement('p');
        descSpan.className = 'event-details';
        descSpan.textContent = eventData.details || 'No additional payload context.';

        bodyDiv.appendChild(metaSpan);
        bodyDiv.appendChild(descSpan);

        row.appendChild(headerDiv);
        row.appendChild(bodyDiv);

        // Prepend to feed (newest first)
        feedContainer.insertBefore(row, feedContainer.firstChild);

        // Track last seen ID
        if (eventData.id > lastEventId) {
            lastEventId = eventData.id;
        }

        // Cap feed at 100 rows (drop oldest rows from bottom)
        while (feedContainer.children.length > 100) {
            feedContainer.removeChild(feedContainer.lastChild);
        }

        // Update live counter badge
        if (feedCountBadge) {
            feedCountBadge.textContent = `${feedContainer.children.length} Events`;
        }
    }

    /**
     * Start Server-Sent Events stream
     */
    function initSSE() {
        if (isPollingFallback) return;

        updateStatus('RECONNECTING');

        const streamUrl = `stream_events.php?last_id=${lastEventId}`;
        eventSource = new EventSource(streamUrl);

        eventSource.addEventListener('connected', function (e) {
            failureCount = 0;
            updateStatus('LIVE');
            const placeholder = feedContainer?.querySelector('p');
            if (placeholder && placeholder.textContent.includes('Connecting')) {
                placeholder.textContent = 'Live stream connected. Telemetry incoming...';
            }
        });

        eventSource.addEventListener('security_event', function (e) {
            try {
                const event = JSON.parse(e.data);
                appendEventToFeed(event);
            } catch (err) {
                console.error('Error parsing SSE security event:', err);
            }
        });

        eventSource.onerror = function (e) {
            failureCount++;
            console.warn(`SSE connection error (${failureCount}/${MAX_FAILURES_BEFORE_POLL})`);
            
            if (eventSource) {
                eventSource.close();
                eventSource = null;
            }

            if (failureCount >= MAX_FAILURES_BEFORE_POLL) {
                console.warn('SSE failed 3 consecutive times. Activating 10-second polling fallback.');
                activatePollingFallback();
            } else {
                updateStatus('RECONNECTING');
                setTimeout(initSSE, 3000);
            }
        };
    }

    /**
     * Fallback to 10-second polling if SSE is blocked or unsupported
     */
    function activatePollingFallback() {
        if (isPollingFallback) return;
        isPollingFallback = true;
        updateStatus('POLLING');

        // Log fallback activation to server once
        fetch('/api/admin_diagnostics.php?action=log_fallback', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: 'SSE_FAILED_3_TIMES' })
        }).catch(() => {});

        pollEvents();
        pollInterval = setInterval(pollEvents, 10000);
    }

    /**
     * Polling fallback fetch routine
     */
    function pollEvents() {
        fetch(`stream_events.php?last_id=${lastEventId}`, {
            headers: { 'Accept': 'application/json' }
        })
            .then(res => res.json())
            .then(data => {
                if (Array.isArray(data)) {
                    data.forEach(appendEventToFeed);
                }
            })
            .catch(err => {
                console.warn('Poll fallback error:', err);
                updateStatus('OFFLINE');
            });
    }

    // Filter events by severity on change
    if (severityFilter) {
        severityFilter.addEventListener('change', function () {
            const filterValue = this.value;
            const rows = feedContainer.querySelectorAll('.feed-event-row');
            rows.forEach(row => {
                if (filterValue === 'all' || row.getAttribute('data-severity') === filterValue) {
                    row.style.display = 'block';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    }

    // Initialize on DOM load
    document.addEventListener('DOMContentLoaded', function () {
        const existingRows = feedContainer?.querySelectorAll('.feed-event-row');
        if (existingRows && existingRows.length > 0) {
            existingRows.forEach(r => {
                const id = parseInt(r.id.replace('event-row-', ''));
                if (!isNaN(id) && id > lastEventId) {
                    lastEventId = id;
                }
            });
            if (feedCountBadge) {
                feedCountBadge.textContent = `${existingRows.length} Events`;
            }
        }

        if (window.EventSource) {
            initSSE();
        } else {
            activatePollingFallback();
        }
    });

    // Cleanup on page unload
    window.addEventListener('beforeunload', function () {
        if (eventSource) {
            eventSource.close();
        }
        if (pollInterval) {
            clearInterval(pollInterval);
        }
    });

})();
