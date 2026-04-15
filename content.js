/**
 * Content Script
 *
 * Detects password input fields on the page and offers to autofill credentials
 * stored in the vault that match the current domain. All communication is done
 * via chrome.runtime.sendMessage so the plaintext data never leaves the
 * extension's trusted context.
 */

"use strict";

(function () {
  // Avoid running more than once per page load
  if (window.__pmInjected) return;
  window.__pmInjected = true;

  /**
   * Find the username field that is visually closest to (and above) the given
   * password field, searching common selector patterns.
   */
  function findUsernameField(passwordField) {
    const selectors = [
      'input[type="email"]',
      'input[type="text"][name*="user"]',
      'input[type="text"][name*="email"]',
      'input[type="text"][name*="login"]',
      'input[type="text"][id*="user"]',
      'input[type="text"][id*="email"]',
      'input[type="text"][id*="login"]',
      'input[type="text"]',
    ];

    const form = passwordField.closest("form");
    const scope = form || document;

    for (const sel of selectors) {
      const field = scope.querySelector(sel);
      if (field && field !== passwordField) return field;
    }
    return null;
  }

  /**
   * Create a small "🔐 Autofill" button that appears at the top-right of the
   * password field without shifting the page layout.
   */
  function createAutofillButton() {
    const btn = document.createElement("button");
    btn.type        = "button";
    btn.textContent = "🔐 Autofill";
    btn.setAttribute("aria-label", "Autofill saved password");

    Object.assign(btn.style, {
      position:     "absolute",
      zIndex:       "2147483647",
      background:   "#6c63ff",
      color:        "#fff",
      border:       "none",
      borderRadius: "4px",
      padding:      "3px 8px",
      fontSize:     "11px",
      cursor:       "pointer",
      fontFamily:   "system-ui, sans-serif",
      boxShadow:    "0 2px 6px rgba(0,0,0,.35)",
      lineHeight:   "1.4",
      pointerEvents: "auto",
      whiteSpace:   "nowrap",
    });
    return btn;
  }

  /**
   * Position `btn` relative to `field` using absolute coordinates.
   */
  function positionButton(btn, field) {
    const rect = field.getBoundingClientRect();
    btn.style.top  = `${window.scrollY + rect.top + 4}px`;
    btn.style.left = `${window.scrollX + rect.right - btn.offsetWidth - 8}px`;
  }

  /**
   * Attach an autofill affordance to a single password field.
   */
  function attachToField(pwField) {
    if (pwField.dataset.pmAttached) return;
    pwField.dataset.pmAttached = "1";

    const btn = createAutofillButton();
    document.body.appendChild(btn);

    // Position on focus
    pwField.addEventListener("focus", async () => {
      positionButton(btn, pwField);
      btn.style.display = "block";

      // Only show the button if we actually have matching credentials
      const response = await chrome.runtime.sendMessage({
        action: "getCredentialsForUrl",
        url:    window.location.href,
      }).catch(() => null);

      if (!response?.entries?.length) {
        btn.style.display = "none";
      }
    });

    pwField.addEventListener("blur", () => {
      // Short delay so a click on the button still registers
      setTimeout(() => { btn.style.display = "none"; }, 200);
    });

    btn.addEventListener("click", async () => {
      const response = await chrome.runtime.sendMessage({
        action: "getCredentialsForUrl",
        url:    window.location.href,
      }).catch(() => null);

      if (!response?.entries?.length) return;

      // Use the first matching credential
      const cred = response.entries[0];
      const usernameField = findUsernameField(pwField);
      if (usernameField) {
        usernameField.value = cred.username;
        usernameField.dispatchEvent(new Event("input",  { bubbles: true }));
        usernameField.dispatchEvent(new Event("change", { bubbles: true }));
      }
      pwField.value = cred.password;
      pwField.dispatchEvent(new Event("input",  { bubbles: true }));
      pwField.dispatchEvent(new Event("change", { bubbles: true }));

      btn.style.display = "none";
    });

    // Update position on scroll / resize so the button tracks the field
    window.addEventListener("scroll", () => positionButton(btn, pwField), { passive: true });
    window.addEventListener("resize", () => positionButton(btn, pwField), { passive: true });
  }

  /**
   * Scan the DOM for password fields and attach the autofill button to each.
   */
  function scanForPasswordFields() {
    document.querySelectorAll('input[type="password"]').forEach(attachToField);
  }

  // Initial scan
  scanForPasswordFields();

  // Observe dynamic DOM changes (SPAs, lazy-loaded forms)
  const observer = new MutationObserver(mutations => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.matches?.('input[type="password"]')) {
          attachToField(node);
        } else {
          node.querySelectorAll?.('input[type="password"]').forEach(attachToField);
        }
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
})();
