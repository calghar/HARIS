// CSRF: add the session token to every same-origin state-changing fetch
(function() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  const token = meta ? meta.content : '';
  const safe = ['GET', 'HEAD', 'OPTIONS'];
  const nativeFetch = globalThis.fetch;
  globalThis.fetch = function(input, init) {
    const opts = init || {};
    const source = input instanceof Request ? input : null;
    const method = (opts.method || (source && source.method) || 'GET').toUpperCase();
    const url = new URL(source ? source.url : String(input), globalThis.location.href);
    if (!safe.includes(method) && url.origin === globalThis.location.origin) {
      const headers = new Headers(opts.headers || (source && source.headers));
      if (!headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', token);
      opts.headers = headers;
    }
    return nativeFetch.call(this, input, opts);
  };
})();

// Shared helpers for page scripts (no inline handlers: pages use data-action)
globalThis.haris = {
  actions(handlers) {
    document.addEventListener('click', function(e) {
      const el = e.target.closest('[data-action]');
      const handler = el && handlers[el.dataset.action];
      if (handler) handler(el, e);
    });
  },
  pageData() {
    const node = document.getElementById('page-data');
    return node ? JSON.parse(node.textContent) : {};
  },
  // LLM markdown is untrusted: sanitise before it reaches innerHTML
  setMarkdown(el, text) {
    if (typeof marked === 'undefined' || typeof DOMPurify === 'undefined') {
      el.textContent = text;
      return;
    }
    el.innerHTML = DOMPurify.sanitize(marked.parse(text, { breaks: true, gfm: true }));
  },
  setSpinner(el, text, small) {
    const spinner = document.createElement('span');
    spinner.className = small ? 'spinner spinner-sm' : 'spinner';
    el.replaceChildren(spinner, document.createTextNode(text ? ' ' + text : ''));
  },
  fillBackends(select, saved) {
    return fetch('/api/v1/llm/backends')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        select.replaceChildren();
        data.backends.forEach(function(b) {
          const opt = new Option(b.available ? b.name : b.name + ' (unavailable)', b.name);
          opt.disabled = !b.available;
          opt.selected = saved ? b.name === saved : b.name === data.default;
          select.appendChild(opt);
        });
      })
      .catch(function() { select.replaceChildren(new Option('anthropic', 'anthropic')); });
  },
  async errorMessage(resp) {
    const body = await resp.json().catch(function() { return {}; });
    return body.detail || body.error || 'Request failed';
  },
};

// Theme
function toggleTheme() {
  const html = document.documentElement;
  const next = html.dataset.theme === 'dark' ? 'light' : 'dark';
  html.dataset.theme = next;
  localStorage.setItem('haris-theme', next);
  updateThemeIcon(next);
}
function updateThemeIcon(theme) {
  document.getElementById('theme-icon-sun').style.display = theme === 'dark' ? '' : 'none';
  document.getElementById('theme-icon-moon').style.display = theme === 'light' ? '' : 'none';
}
updateThemeIcon(document.documentElement.dataset.theme);

// Tab switching
document.addEventListener('click', function(e) {
  if (!e.target.classList.contains('tab')) return;
  const group = e.target.closest('.tabs');
  const target = e.target.dataset.tab;
  group.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
  e.target.classList.add('active');
  document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });
  const panel = document.getElementById(target);
  if (panel) panel.classList.add('active');
});

// Mobile nav: close on link click
document.querySelectorAll('#main-nav a').forEach(function(a) {
  a.addEventListener('click', function() {
    document.getElementById('main-nav').classList.remove('open');
  });
});

// Hamburger toggle
document.querySelector('.hamburger')?.addEventListener('click', function() {
  document.getElementById('main-nav').classList.toggle('open');
});

// Theme toggle button
document.getElementById('theme-toggle')?.addEventListener('click', toggleTheme);

// User menu popup
(function() {
  const trigger = document.getElementById('user-menu-trigger');
  const popup   = document.getElementById('user-menu-popup');
  if (!trigger || !popup) return;

  function open() {
    popup.classList.add('open');
    trigger.classList.add('open');
    trigger.setAttribute('aria-expanded', 'true');
    popup.setAttribute('aria-hidden', 'false');
  }
  function close() {
    popup.classList.remove('open');
    trigger.classList.remove('open');
    trigger.setAttribute('aria-expanded', 'false');
    popup.setAttribute('aria-hidden', 'true');
  }

  trigger.addEventListener('click', function(e) {
    e.stopPropagation();
    popup.classList.contains('open') ? close() : open();
  });
  document.addEventListener('click', close);
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') { close(); trigger.focus(); }
  });
})();
