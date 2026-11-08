(function() {
  function dashFilter() {
    const hostname = document.getElementById('dash-hostname').value;
    const severity = document.getElementById('dash-severity').value;
    const params = new URLSearchParams({ format: 'html', per_page: '5' });
    if (hostname) params.set('hostname', hostname);
    if (severity) params.set('severity', severity);
    htmx.ajax('GET', '/api/scans?' + params, '#dash-scan-table');
  }
  document.getElementById('dash-hostname').addEventListener('change', dashFilter);
  document.getElementById('dash-severity').addEventListener('change', dashFilter);
})();
