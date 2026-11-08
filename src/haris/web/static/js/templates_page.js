(function() {
  const REFRESH_DELAY_MS = 800;

  function request(url, method, body) {
    const opts = { method: method };
    if (body !== undefined) {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(body);
    }
    return fetch(url, opts).then(async function(res) {
      if (!res.ok) throw new Error(await haris.errorMessage(res));
      return res.json();
    });
  }

  function fail(err) { alert('Error: ' + err.message); }

  function setStatus(el, cls, text) {
    const span = document.createElement('span');
    span.className = cls;
    span.textContent = text;
    el.replaceChildren(span);
  }

  function withSpinner(el) {
    const spinner = document.createElement('span');
    spinner.className = 'spinner spinner-sm';
    el.replaceChildren(spinner);
  }

  function updateSources(statusEls, payload, onDone) {
    return fetch('/api/v1/templates/update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
      .then(async function(res) { return { ok: res.ok, detail: res.ok ? '' : await haris.errorMessage(res) }; })
      .then(function(result) {
        onDone();
        if (result.ok) {
          statusEls.forEach(function(el) { setStatus(el, 'src-ok', 'Updated — reloading...'); });
          setTimeout(function() { globalThis.location.reload(); }, REFRESH_DELAY_MS);
        } else {
          statusEls.forEach(function(el) { setStatus(el, 'src-fail', 'Failed: ' + result.detail); });
        }
      })
      .catch(function(err) {
        onDone();
        statusEls.forEach(function(el) { setStatus(el, 'src-fail', 'Error: ' + err.message); });
      });
  }

  haris.actions({
    'delete-template': function(el) {
      const id = el.dataset.templateId;
      if (!confirm('Delete configuration "' + el.dataset.templateName + '"? This cannot be undone.')) return;
      request('/api/v1/scan-templates/' + encodeURIComponent(id), 'DELETE')
        .then(function() {
          const card = document.getElementById('tpl-' + id);
          if (!card) return;
          card.classList.add('card-removing');
          setTimeout(function() { card.remove(); }, 260);
        })
        .catch(fail);
    },
    'set-default-template': function(el) {
      request('/api/v1/scan-templates/' + encodeURIComponent(el.dataset.templateId) + '/set-default', 'POST')
        .then(function() { globalThis.location.reload(); })
        .catch(fail);
    },
    'clone-template': function(el) {
      request('/api/v1/scan-templates/' + encodeURIComponent(el.dataset.templateId), 'GET')
        .then(function(tpl) {
          tpl.name = 'Copy of ' + el.dataset.templateName;
          ['template_id', 'is_default', 'created_at', 'updated_at'].forEach(function(k) { delete tpl[k]; });
          return request('/api/v1/scan-templates', 'POST', tpl);
        })
        .then(function() { globalThis.location.reload(); })
        .catch(fail);
    },
    'update-source': function(el) {
      const status = document.getElementById('src-status-' + el.dataset.index);
      withSpinner(status);
      updateSources([status], { scanner: el.dataset.scanner, source_name: el.dataset.source }, function() {});
    },
    'update-all-sources': function(el) {
      const icon = el.querySelector('svg');
      const label = el.querySelector('.btn-label');
      const idle = label.textContent;
      el.disabled = true;
      label.textContent = 'Updating...';
      if (icon) icon.style.display = 'none';
      const statuses = Array.from(document.querySelectorAll('.src-status'));
      statuses.forEach(function(s) { setStatus(s, 'src-muted', 'Queued...'); });
      updateSources(statuses, {}, function() {
        el.disabled = false;
        label.textContent = idle;
        if (icon) icon.style.display = '';
      });
    },
  });
})();
