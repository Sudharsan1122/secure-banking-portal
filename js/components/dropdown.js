/**
 * SecureBank Design System — Dropdown Engine (dropdown.js)
 * Accessible click/keyboard dropdown navigation
 */
(function () {
  'use strict';

  function closeAllDropdowns() {
    document.querySelectorAll('.dropdown.open').forEach(function (d) {
      d.classList.remove('open');
      var trigger = d.querySelector('[data-dropdown-toggle]');
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
    });
  }

  document.addEventListener('click', function (e) {
    var trigger = e.target.closest('[data-dropdown-toggle]');
    if (trigger) {
      var dropdown = trigger.closest('.dropdown');
      if (dropdown) {
        var isOpen = dropdown.classList.contains('open');
        closeAllDropdowns();
        if (!isOpen) {
          dropdown.classList.add('open');
          trigger.setAttribute('aria-expanded', 'true');
        }
        e.stopPropagation();
        return;
      }
    }

    if (!e.target.closest('.dropdown-menu')) {
      closeAllDropdowns();
    }
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      closeAllDropdowns();
    }
  });

  window.SecureBankDropdown = {
    closeAll: closeAllDropdowns
  };
})();
