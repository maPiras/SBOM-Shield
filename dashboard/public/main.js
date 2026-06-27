// ── Dark mode ──────────────────────────────────────────────────────────────
(function () {
  'use strict';

  var MOON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  var SUN  = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';

  var root = document.documentElement;

  function updateIcon() {
    var isDark = root.getAttribute('data-theme') === 'dark';
    var btn = document.getElementById('dark-toggle');
    if (btn) btn.innerHTML = isDark ? SUN : MOON;
  }

  updateIcon();

  var btn = document.getElementById('dark-toggle');
  if (btn) {
    btn.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
      updateIcon();
      window.dispatchEvent(new CustomEvent('themechange'));
    });
  }
})();

// ── Login ───────────────────────────────────────────────────────────────────
(function () {
  'use strict';

  const API = '/api/v1';

  const overlay   = document.getElementById('login-overlay');
  const panel     = document.getElementById('login-panel');
  const btnAccess = document.getElementById('btn-access');
  const btnClose  = document.getElementById('login-close');
  const form      = document.querySelector('.login-form');
  const btnLogin  = form ? form.querySelector('.btn-login') : null;

  // ── Overlay open/close ──────────────────────────────────────────

  function openLogin() {
    overlay.classList.add('active');
    overlay.setAttribute('aria-hidden', 'false');
    setTimeout(() => {
      const first = overlay.querySelector('input');
      if (first) first.focus();
    }, 350);
  }

  function closeLogin() {
    overlay.classList.remove('active');
    overlay.setAttribute('aria-hidden', 'true');
    clearError();
  }

  if (btnAccess) btnAccess.addEventListener('click', openLogin);
  if (btnClose)  btnClose.addEventListener('click', closeLogin);

  overlay.addEventListener('click', (e) => {
    if (!panel.contains(e.target)) closeLogin();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && overlay.classList.contains('active')) closeLogin();
  });

  // ── Error display ───────────────────────────────────────────────

  function showError(msg) {
    let el = form.querySelector('.login-error');
    if (!el) {
      el = document.createElement('p');
      el.className = 'login-error';
      btnLogin.insertAdjacentElement('beforebegin', el);
    }
    el.textContent = msg;
  }

  function clearError() {
    const el = form ? form.querySelector('.login-error') : null;
    if (el) el.remove();
  }

  // ── Login submit ────────────────────────────────────────────────

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearError();

      const email    = form.querySelector('#email').value.trim();
      const password = form.querySelector('#password').value;

      if (!email || !password) {
        showError('Compila tutti i campi.');
        return;
      }

      setLoading(true);

      try {
        const res = await fetch(`${API}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });

        const data = await res.json();

        if (!res.ok) {
          showError(data.detail || 'Credenziali non valide.');
          return;
        }

        sessionStorage.setItem('access_token',  data.access_token);
        sessionStorage.setItem('refresh_token', data.refresh_token);

        window.location.href = '/dashboard/user.html';

      } catch (err) {
        showError('Errore di rete. Riprova.');
      } finally {
        setLoading(false);
      }
    });
  }

  function setLoading(loading) {
    if (!btnLogin) return;
    btnLogin.disabled = loading;
    btnLogin.querySelector('span').textContent = loading ? 'Verifica...' : 'Authenticate';
  }

})();
