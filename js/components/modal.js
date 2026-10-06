/**
 * SecureBank Design System — Modal Engine (modal.js)
 * Accessible Modal with Focus Trap & Escape Key Listener
 */
(function () {
  'use strict';

  var lastFocusedElement = null;

  function getFocusableElements(element) {
    return element.querySelectorAll(
      'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );
  }

  function trapFocus(e, modal) {
    var focusables = getFocusableElements(modal);
    if (focusables.length === 0) return;

    var first = focusables[0];
    var last = focusables[focusables.length - 1];

    if (e.key === 'Tab') {
      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }
  }

  function openModal(modalId) {
    var overlay = document.getElementById(modalId);
    if (!overlay) return;

    lastFocusedElement = document.activeElement;
    overlay.classList.add('active');
    overlay.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';

    var modal = overlay.querySelector('.modal');
    if (modal) {
      var focusables = getFocusableElements(modal);
      if (focusables.length > 0) {
        focusables[0].focus();
      }
    }
  }

  function closeModal(modalId) {
    var overlay = typeof modalId === 'string' ? document.getElementById(modalId) : modalId;
    if (!overlay) {
      overlay = document.querySelector('.modal-overlay.active');
    }
    if (!overlay) return;

    overlay.classList.remove('active');
    overlay.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';

    if (lastFocusedElement && typeof lastFocusedElement.focus === 'function') {
      lastFocusedElement.focus();
      lastFocusedElement = null;
    }
  }

  // Global listeners
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      var activeModal = document.querySelector('.modal-overlay.active');
      if (activeModal) {
        closeModal(activeModal);
      }
    } else if (e.key === 'Tab') {
      var currentModal = document.querySelector('.modal-overlay.active .modal');
      if (currentModal) {
        trapFocus(e, currentModal);
      }
    }
  });

  document.addEventListener('DOMContentLoaded', function () {
    // Backdrop click dismisses
    document.querySelectorAll('.modal-overlay').forEach(function (overlay) {
      overlay.addEventListener('click', function (e) {
        if (e.target === overlay) {
          closeModal(overlay);
        }
      });
    });

    // Close buttons
    document.querySelectorAll('[data-modal-close]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var targetId = btn.getAttribute('data-modal-close');
        if (targetId) {
          closeModal(targetId);
        } else {
          var parentOverlay = btn.closest('.modal-overlay');
          if (parentOverlay) closeModal(parentOverlay);
        }
      });
    });

    // Open triggers
    document.querySelectorAll('[data-modal-target]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var targetId = btn.getAttribute('data-modal-target');
        if (targetId) openModal(targetId);
      });
    });
  });

  window.SecureBankModal = {
    open: openModal,
    close: closeModal
  };
})();
