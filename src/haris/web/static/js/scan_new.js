(function() {
  const data = haris.pageData();
  const profiles = data.profileDescriptions;
  const byId = function(id) { return document.getElementById(id); };

  const templateSelect = byId('scan_template');
  const templateDesc = byId('template-desc');
  const profileSelect = byId('profile');
  const profileDesc = byId('profile-desc');
  const authGroup = byId('auth-header-group');
  const llmCheckbox = byId('llm_enrich');
  const llmOptions = byId('llm-options');
  let llmBackendsLoaded = false;

  function showAuthGroup(method) {
    authGroup.style.display = (method === 'header' || method === 'cookie') ? 'block' : 'none';
  }

  // Template selector: auto-fill the form when a template is chosen
  templateSelect.addEventListener('change', async function() {
    if (!this.value) {
      templateDesc.textContent = 'Select a saved template to auto-fill settings, or configure manually.';
      return;
    }
    try {
      const resp = await fetch('/api/scan-templates/' + encodeURIComponent(this.value));
      if (!resp.ok) return;
      const tpl = await resp.json();
      templateDesc.textContent = tpl.description || '';
      profileSelect.value = tpl.profile || 'quick';
      profileDesc.textContent = profiles[tpl.profile] || '';
      byId('rate_limit').value = tpl.rate_limit_rps || 10;
      byId('max_requests').value = tpl.max_requests || 10000;
      byId('excluded_paths').value = (tpl.excluded_paths || []).join('\n');
      byId('auth_method').value = tpl.auth_method || 'none';
      showAuthGroup(tpl.auth_method);
      document.querySelectorAll('input[name="report_formats"]').forEach(function(cb) {
        cb.checked = (tpl.report_formats || []).includes(cb.value);
      });
      llmCheckbox.checked = !!tpl.llm_enrichment;
      llmCheckbox.dispatchEvent(new Event('change'));
    } catch (e) { /* ignore fetch errors */ }
  });
  if (templateSelect.value) templateSelect.dispatchEvent(new Event('change'));

  profileSelect.addEventListener('change', function() {
    profileDesc.textContent = profiles[profileSelect.value] || '';
  });
  profileDesc.textContent = profiles[profileSelect.value] || '';

  byId('target_url').addEventListener('input', function() {
    byId('url-error').style.display = 'none';
  });

  byId('auth_method').addEventListener('change', function() { showAuthGroup(this.value); });
  showAuthGroup(data.prefillAuthMethod);

  llmCheckbox.addEventListener('change', function() {
    llmOptions.style.display = this.checked ? 'block' : 'none';
    if (this.checked && !llmBackendsLoaded) {
      llmBackendsLoaded = true;
      haris.fillBackends(byId('llm_backend'));
    }
  });

  byId('scan-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    const urlInput = byId('target_url');
    const urlError = byId('url-error');
    const url = urlInput.value.trim();
    if (!url || !/^https?:\/\//i.test(url)) {
      urlError.style.display = '';
      urlInput.focus();
      return;
    }
    urlError.style.display = 'none';
    urlInput.value = url;

    const btn = byId('submit-btn');
    const status = byId('submit-status');
    btn.disabled = true;
    haris.setSpinner(status, 'Starting scan...');
    try {
      const resp = await fetch('/api/scan/start', { method: 'POST', body: new FormData(this) });
      const body = await resp.json();
      if (resp.ok) {
        globalThis.location.href = body.redirect;
      } else {
        status.textContent = 'Error: ' + (body.detail || 'Unknown error');
        btn.disabled = false;
      }
    } catch (err) {
      status.textContent = 'Network error: ' + err.message;
      btn.disabled = false;
    }
  });
})();
