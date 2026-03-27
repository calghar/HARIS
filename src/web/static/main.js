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
