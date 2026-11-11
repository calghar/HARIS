(function() {
  // ----------------------------------------------------------------
  // Profile → scanner mapping (mirrors src/haris/core/profiles.py)
  // ----------------------------------------------------------------
  const data = haris.pageData();
  const PROFILE_SCANNERS = data.profileScanners;
  const profileDescriptions = data.profileDescriptions;

  // External-tool panels (built-ins panel is always shown)
  const SCANNER_PANELS = {
    "nuclei":  document.getElementById("panel-nuclei"),
    "nikto":   document.getElementById("panel-nikto"),
    "nmap":    document.getElementById("panel-nmap"),
    "wapiti":  document.getElementById("panel-wapiti"),
    "sslyze":  document.getElementById("panel-sslyze"),
  };

  function updateScannerPanels(profileName) {
    const scanners = PROFILE_SCANNERS[profileName] || [];
    Object.entries(SCANNER_PANELS).forEach(([name, el]) => {
      if (!el) return;
      const visible = scanners.includes(name);
      el.style.display = visible ? "" : "none";
      if (!visible) el.classList.remove("open");
    });
  }

  const profileSelect = document.getElementById("profile");
  const profileDesc   = document.getElementById("profile-desc");

  profileSelect.addEventListener("change", function() {
    profileDesc.textContent = profileDescriptions[this.value] || "";
    updateScannerPanels(this.value);
  });

  // Initialise on page load
  profileDesc.textContent = profileDescriptions[profileSelect.value] || "";
  updateScannerPanels(profileSelect.value);

  // ----------------------------------------------------------------
  // LLM enrichment toggle
  // ----------------------------------------------------------------
  const llmCheckbox    = document.getElementById("llm_enrichment");
  const llmBackendGrp  = document.getElementById("llm-backend-group");
  let llmBackendsLoaded = false;

  function syncLlmPanel() {
    llmBackendGrp.style.display = llmCheckbox.checked ? "block" : "none";
    if (llmCheckbox.checked && !llmBackendsLoaded) {
      llmBackendsLoaded = true;
      fetch("/api/v1/llm/backends")
        .then(r => r.json())
        .then(data => {
          const sel = document.getElementById("llm_backend");
          sel.replaceChildren();
          data.backends.forEach(b => {
            const opt = document.createElement("option");
            opt.value = b.name;
            opt.textContent = b.available ? b.name : b.name + " (unavailable)";
            opt.disabled = !b.available;
            // In edit mode honour the saved backend, otherwise pick the default
            const saved = data.savedBackend;
            if (saved ? b.name === saved : b.name === data.default) opt.selected = true;
            sel.appendChild(opt);
          });
        })
        .catch(() => {
          document.getElementById("llm_backend").replaceChildren(new Option("anthropic", "anthropic"));
        });
    }
  }

  llmCheckbox.addEventListener("change", syncLlmPanel);
  // Trigger immediately if checked (edit mode with enrichment on)
  if (llmCheckbox.checked) syncLlmPanel();

  haris.actions({
    'toggle-panel': function(el) { el.parentElement.classList.toggle('open'); },
    'set-value': function(el) { document.getElementById(el.dataset.target).value = el.dataset.value; },
    'add-wapiti-module': function(el) { addWapitiModule(el.dataset.module); },
  });

  // ----------------------------------------------------------------
  // Wapiti module quick-add helper
  // ----------------------------------------------------------------
  function addWapitiModule(mod) {
    const inp = document.getElementById("wapiti_modules");
    if (inp.value === "all") {
      inp.value = mod;
      return;
    }
    const parts = inp.value.split(",").map(s => s.trim()).filter(Boolean);
    if (!parts.includes(mod)) parts.push(mod);
    inp.value = parts.join(",");
  }

  // ----------------------------------------------------------------
  // Collect form data → structured JSON payload
  // ----------------------------------------------------------------
  function collectFormData() {
    const get  = id => document.getElementById(id);
    const vals = name => [...document.querySelectorAll(`[name="${name}"]:checked`)].map(el => el.value);

    // Scanner options
    const scannerOptions = {};

    // Nuclei
    const nucleiPanel = get("panel-nuclei");
    if (nucleiPanel && nucleiPanel.style.display !== "none") {
      const tags = vals("nuclei_tags");
      const customRaw = (get("nuclei_custom_tags").value || "").trim();
      if (customRaw) {
        customRaw.split(",").map(s => s.trim()).filter(Boolean).forEach(t => {
          if (!tags.includes(t)) tags.push(t);
        });
      }
      scannerOptions.nuclei = {
        template_dirs: vals("nuclei_template_dirs"),
        tags: tags,
        severity: vals("nuclei_severity"),
        exclude_tags: vals("nuclei_exclude_tags"),
        rate_limit: parseInt(get("nuclei_rate_limit").value, 10) || 150,
        max_host_errors: parseInt(get("nuclei_max_host_errors").value, 10) || 500,
        timeout: parseInt(get("nuclei_timeout").value, 10) || 600,
      };
    }

    // Nikto
    const niktoPanel = get("panel-nikto");
    if (niktoPanel && niktoPanel.style.display !== "none") {
      scannerOptions.nikto = {
        tuning: vals("nikto_tuning"),
        timeout: parseInt(get("nikto_timeout").value, 10) || 300,
      };
    }

    // Nmap
    const nmapPanel = get("panel-nmap");
    if (nmapPanel && nmapPanel.style.display !== "none") {
      scannerOptions.nmap = {
        ports: get("nmap_ports").value.trim() || "80,443,8080,8443",
        script_categories: vals("nmap_script_categories"),
        timeout: parseInt(get("nmap_timeout").value, 10) || 300,
      };
    }

    // Wapiti
    const wapitiPanel = get("panel-wapiti");
    if (wapitiPanel && wapitiPanel.style.display !== "none") {
      scannerOptions.wapiti = {
        modules: get("wapiti_modules").value.trim() || "all",
        scope: get("wapiti_scope").value,
        max_scan_time: parseInt(get("wapiti_max_scan_time").value, 10) || 600,
        max_links: parseInt(get("wapiti_max_links").value, 10) || 500,
        timeout: parseInt(get("wapiti_timeout").value, 10) || 300,
      };
    }

    // SSLyze
    const sslyzePanel = get("panel-sslyze");
    if (sslyzePanel && sslyzePanel.style.display !== "none") {
      scannerOptions.sslyze = {
        timeout: parseInt(get("sslyze_timeout").value, 10) || 120,
      };
    }

    // Built-in checks (always collected)
    scannerOptions.header_checks = {
      follow_redirects: get("header_checks_follow_redirects").checked,
    };
    scannerOptions.tls_checks = {
      cert_expiry_warn_days: parseInt(get("tls_cert_expiry_warn_days").value, 10) || 30,
    };
    scannerOptions.misc_checks = {
      check_cors:             document.querySelector('[name="check_cors"]').checked,
      check_redirect:         document.querySelector('[name="check_redirect"]').checked,
      check_sensitive_paths:  document.querySelector('[name="check_sensitive_paths"]').checked,
    };
    scannerOptions.info_disclosure = {
      check_error_pages:       document.querySelector('[name="check_error_pages"]').checked,
      check_debug_endpoints:   document.querySelector('[name="check_debug_endpoints"]').checked,
      check_html_comments:     document.querySelector('[name="check_html_comments"]').checked,
      check_version_endpoints: document.querySelector('[name="check_version_endpoints"]').checked,
    };

    // Tags
    const tagsRaw = get("tags").value.trim();
    const tagsArr = tagsRaw
      ? tagsRaw.split(",").map(s => s.trim()).filter(Boolean)
      : [];

    // Excluded paths
    const excludedRaw = get("excluded_paths").value.trim();
    const excludedArr = excludedRaw
      ? excludedRaw.split("\n").map(s => s.trim()).filter(Boolean)
      : [];

    // Report formats
    const reportFormats = vals("report_formats");

    return {
      name:            get("name").value.trim(),
      description:     get("description").value.trim(),
      profile:         get("profile").value,
      rate_limit_rps:  parseFloat(get("rate_limit_rps").value) || 10,
      max_requests:    parseInt(get("max_requests").value, 10) || 10000,
      excluded_paths:  excludedArr,
      auth_method:     get("auth_method").value,
      report_formats:  reportFormats,
      llm_enrichment:  get("llm_enrichment").checked,
      llm_backend:     llmCheckbox.checked ? (get("llm_backend").value || "") : "",
      scanner_options: scannerOptions,
      tags:            tagsArr,
    };
  }

  // ----------------------------------------------------------------
  // Form submit — POST (create) or PUT (edit)
  // ----------------------------------------------------------------
  document.getElementById("template-form").addEventListener("submit", async function(e) {
    e.preventDefault();
    const btn    = document.getElementById("submit-btn");
    const status = document.getElementById("submit-status");

    const payload = collectFormData();
    if (!payload.name) {
      status.textContent = "Template name is required.";
      return;
    }

    btn.disabled = true;
    haris.setSpinner(status, "Saving...");

    try {
      const url = data.templateId
        ? "/api/v1/scan-templates/" + encodeURIComponent(data.templateId)
        : "/api/v1/scan-templates";
      const resp = await fetch(url, {
        method: data.templateId ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const body = await resp.json();
      if (resp.ok) {
        window.location.href = "/templates";
      } else {
        status.textContent = "Error: " + (body.detail || JSON.stringify(body));
        btn.disabled = false;
      }
    } catch (err) {
      status.textContent = "Network error: " + err.message;
      btn.disabled = false;
    }
  });

  // ----------------------------------------------------------------
  // Edit mode: pre-populate scanner_options fields
  // (Jinja has already set basic inputs via value= attributes.
  //  The JS below handles list-of-strings fields that Jinja can't
  //  easily populate without server-side loops inside JS, and
  //  also handles any mis-match between Jinja defaults vs saved data.)
  // ----------------------------------------------------------------
  if (data.scannerOptions) (function() {
    const so = data.scannerOptions;

    // Nuclei — uncheck all, then check saved ones
    if (so.nuclei && Array.isArray(so.nuclei.template_dirs)) {
      document.querySelectorAll('[name="nuclei_template_dirs"]').forEach(cb => {
        cb.checked = so.nuclei.template_dirs.includes(cb.value);
      });
    }
    if (so.nuclei && Array.isArray(so.nuclei.tags)) {
      document.querySelectorAll('[name="nuclei_tags"]').forEach(cb => {
        cb.checked = so.nuclei.tags.includes(cb.value);
      });
    }
    if (so.nuclei && Array.isArray(so.nuclei.severity)) {
      document.querySelectorAll('[name="nuclei_severity"]').forEach(cb => {
        cb.checked = so.nuclei.severity.includes(cb.value);
      });
    }
    if (so.nuclei && Array.isArray(so.nuclei.exclude_tags)) {
      document.querySelectorAll('[name="nuclei_exclude_tags"]').forEach(cb => {
        cb.checked = so.nuclei.exclude_tags.includes(cb.value);
      });
    }

    // Nikto tuning
    if (so.nikto && Array.isArray(so.nikto.tuning)) {
      document.querySelectorAll('[name="nikto_tuning"]').forEach(cb => {
        cb.checked = so.nikto.tuning.includes(cb.value);
      });
    }

    // Nmap script categories
    if (so.nmap && Array.isArray(so.nmap.script_categories)) {
      document.querySelectorAll('[name="nmap_script_categories"]').forEach(cb => {
        cb.checked = so.nmap.script_categories.includes(cb.value);
      });
    }
  })();
})();
