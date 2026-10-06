/**
 * SecureBank Profile & Security Settings Client Script (profile.js)
 * 
 * MODULE 4: PROFILE CREDENTIALS & PASSWORD ROTATION
 * PILLAR A [A8]: MULTI-LAYER SANITIZED AVATAR UPLOADS
 * PILLAR C [C4]: SECURITY POSTURE SCORE GAUGE & RUBRIC
 * PILLAR E: TWO-COLUMN FINTECH PROFILE, DEVICES LIST & DANGER ZONE
 * 
 * Strict Security Defenses:
 * - textContent used for DOM rendering (XSS defense)
 * - CSRF token included on all POST requests
 * - No inline scripts
 */

document.addEventListener('DOMContentLoaded', async () => {
    const passwordForm = document.getElementById('passwordForm');
    const savePasswordBtn = document.getElementById('savePasswordBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const avatarForm = document.getElementById('avatarForm');
    const avatarFile = document.getElementById('avatarFile');
    const btnUploadAvatar = document.getElementById('btnUploadAvatar');
    const avatarImg = document.getElementById('avatarImg');
    const profileAvatarInitials = document.getElementById('profileAvatarInitials');

    // Sign Out Handler
    logoutBtn?.addEventListener('click', async () => {
        try {
            await fetch('../api/logout.php', { method: 'POST' });
        } finally {
            sessionStorage.clear();
            window.location.href = 'login.html';
        }
    });

    // 1. Load Profile Identity
    async function loadProfile() {
        try {
            const res = await fetch('../api/profile.php', { headers: { 'Accept': 'application/json' } });
            if (res.status === 401) {
                window.location.href = 'login.html?msg=expired';
                return;
            }
            const json = await res.json();
            if (json.status === 'success') {
                const u = json.data;
                const setText = (id, val) => {
                    const el = document.getElementById(id);
                    if (el) el.textContent = val;
                };

                setText('profName', u.name);
                setText('profHeaderName', u.name);
                setText('profUsername', u.username);
                setText('profHeaderUsername', `@${u.username}`);
                setText('profEmail', u.email);
                setText('profPhone', u.phone);
                setText('profAccount', u.account_number);
                setText('profRole', u.role ? u.role.toUpperCase() : 'USER');
                setText('profCreated', u.created_at);

                if (profileAvatarInitials && u.name) {
                    const parts = u.name.trim().split(/\s+/);
                    profileAvatarInitials.textContent = (parts[0][0] + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase();
                }

                if (json.csrf_token) {
                    sessionStorage.setItem('csrf_token', json.csrf_token);
                }
            }
        } catch (err) {
            console.error('Profile fetch error:', err);
        }
    }

    // 2. Load Security Posture Score (C4)
    async function loadSecurityScore() {
        try {
            const res = await fetch('../api/security_score.php');
            if (!res.ok) return;
            const json = await res.json();
            if (json.status === 'success') {
                const s = json.data;
                const score = s.score;

                const scoreNumEl = document.getElementById('scoreNumber');
                if (scoreNumEl) scoreNumEl.textContent = score;

                const badge = document.getElementById('scoreLevelBadge');
                if (badge) {
                    badge.textContent = s.level.toUpperCase();
                    badge.style.backgroundColor = s.color || 'var(--color-success)';
                    badge.style.color = '#FFFFFF';
                }

                // Gauge circle animation (circumference = 2 * PI * 58 ≈ 364.4)
                const circle = document.getElementById('scoreGaugeCircle');
                if (circle) {
                    const circumference = 364.4;
                    const offset = circumference - (score / 100) * circumference;
                    circle.style.strokeDashoffset = offset;
                    circle.setAttribute('stroke', s.color || '#00B87C');
                }

                const scoreTitle = document.getElementById('scoreTitle');
                if (scoreTitle) {
                    scoreTitle.textContent = `Security Rating: ${s.level} (${score}/100)`;
                }

                // Render Rubric Items safely with textContent
                const rubricList = document.getElementById('scoreRubricList');
                if (rubricList) {
                    rubricList.textContent = '';
                    s.items.forEach(item => {
                        const row = document.createElement('div');
                        row.style.display = 'flex';
                        row.style.justifyContent = 'space-between';
                        row.style.alignItems = 'center';
                        row.style.padding = '4px 0';
                        row.style.borderBottom = '1px solid var(--border-subtle)';

                        const left = document.createElement('span');
                        left.style.display = 'flex';
                        left.style.alignItems = 'center';
                        left.style.gap = '6px';
                        left.style.color = item.earned ? 'var(--color-success)' : 'var(--text-muted)';
                        left.textContent = (item.earned ? '✓ ' : '✕ ') + item.name;

                        const right = document.createElement('strong');
                        right.className = 'mono';
                        right.style.fontSize = '0.75rem';
                        right.textContent = item.earned ? `+${item.points} pts` : `0 pts`;
                        right.style.color = item.earned ? 'var(--color-success)' : 'var(--color-danger)';

                        row.appendChild(left);
                        row.appendChild(right);
                        rubricList.appendChild(row);
                    });
                }

                // Render Recommendations safely
                const tipsList = document.getElementById('scoreTipsList');
                if (tipsList) {
                    tipsList.textContent = '';
                    if (!s.recommendations || s.recommendations.length === 0) {
                        const li = document.createElement('li');
                        li.textContent = 'Maximum security posture achieved! Keep maintaining your MFA and credentials.';
                        tipsList.appendChild(li);
                    } else {
                        s.recommendations.forEach(tip => {
                            const li = document.createElement('li');
                            li.textContent = tip;
                            tipsList.appendChild(li);
                        });
                    }
                }
            }
        } catch (err) {
            console.warn('Error loading security score:', err);
        }
    }

    // 3. Password Rotation Form
    passwordForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const current_password = document.getElementById('currentPassword').value;
        const new_password = document.getElementById('newPassword').value;
        const confirm_password = document.getElementById('confirmPassword').value;

        if (new_password !== confirm_password) {
            showToast('New passwords do not match.', 'error');
            return;
        }

        savePasswordBtn.disabled = true;
        savePasswordBtn.textContent = 'Updating Password...';

        try {
            const csrfToken = sessionStorage.getItem('csrf_token') || '';
            const res = await fetch('../api/profile.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    action: 'change_password',
                    current_password,
                    new_password
                })
            });

            const json = await res.json();

            if (res.ok && json.status === 'success') {
                showToast('Master password updated successfully!', 'success');
                passwordForm.reset();
                loadSecurityScore(); // Refresh score
            } else {
                const msg = json.errors ? json.errors.join(' ') : (json.message || 'Password update failed.');
                showToast(msg, 'error');
            }
        } catch (err) {
            showToast('Network error updating password.', 'error');
        } finally {
            savePasswordBtn.disabled = false;
            savePasswordBtn.textContent = 'Update Password';
        }
    });

    // 4. Avatar Upload Handler (Pillar A [A8])
    avatarForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!avatarFile || !avatarFile.files || avatarFile.files.length === 0) {
            showToast('Please select an image file first.', 'error');
            return;
        }

        btnUploadAvatar.disabled = true;
        btnUploadAvatar.textContent = 'Sanitizing...';

        const formData = new FormData();
        formData.append('avatar', avatarFile.files[0]);

        try {
            const csrfToken = sessionStorage.getItem('csrf_token') || '';
            const res = await fetch('../api/avatar.php', {
                method: 'POST',
                headers: { 'X-CSRF-Token': csrfToken },
                body: formData
            });
            const json = await res.json();
            if (res.ok && json.status === 'success') {
                showToast('Avatar sanitized and uploaded successfully!', 'success');
                if (avatarImg) avatarImg.src = json.avatar_url;
                avatarFile.value = '';
            } else {
                showToast(json.message || 'Avatar upload failed.', 'error');
            }
        } catch (err) {
            showToast('Network error uploading avatar.', 'error');
        } finally {
            btnUploadAvatar.disabled = false;
            btnUploadAvatar.textContent = 'Upload & Sanitize Avatar';
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

    loadProfile();
    loadSecurityScore();
});
