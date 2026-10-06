/**
 * SecureBank Design System — Toast System (toast.js)
 * Accessible, WCAG-compliant live-region notifications
 * Strict XSS defense: uses textContent exclusively.
 */
(function () {
  'use strict';

  var container = null;

  function getContainer() {
    if (!container || !document.body.contains(container)) {
      container = document.querySelector('.toast-container');
      if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        container.setAttribute('aria-live', 'polite');
        container.setAttribute('aria-atomic', 'true');
        document.body.appendChild(container);
      }
    }
    return container;
  }

  function showToast(message, type, title) {
    type = type || 'info';
    var toastBox = document.createElement('div');
    toastBox.className = 'toast toast-' + type;
    toastBox.setAttribute('role', 'status');

    var contentWrap = document.createElement('div');
    contentWrap.className = 'toast-content';

    if (title) {
      var titleEl = document.createElement('div');
      titleEl.className = 'toast-title';
      titleEl.textContent = title;
      contentWrap.appendChild(titleEl);
    }

    var msgEl = document.createElement('div');
    msgEl.className = 'toast-message';
    msgEl.textContent = message;
    contentWrap.appendChild(msgEl);

    var closeBtn = document.createElement('button');
    closeBtn.className = 'toast-close';
    closeBtn.setAttribute('aria-label', 'Close notification');
    closeBtn.textContent = '×';

    toastBox.appendChild(contentWrap);
    toastBox.appendChild(closeBtn);

    var c = getContainer();
    c.appendChild(toastBox);

    // Trigger animation
    requestAnimationFrame(function () {
      toastBox.classList.add('show');
    });

    var timer = null;
    var duration = 4000;

    function startTimer() {
      timer = setTimeout(dismiss, duration);
    }

    function stopTimer() {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    }

    function dismiss() {
      stopTimer();
      toastBox.classList.remove('show');
      toastBox.addEventListener('transitionend', function () {
        if (toastBox.parentNode) {
          toastBox.parentNode.removeChild(toastBox);
        }
      }, { once: true });
    }

    closeBtn.addEventListener('click', dismiss);
    toastBox.addEventListener('mouseenter', stopTimer);
    toastBox.addEventListener('mouseleave', startTimer);

    startTimer();
    return toastBox;
  }

  // Export globally
  window.showToast = showToast;
  window.SecureBankToast = { show: showToast };
})();
