haris.actions({
  'clear-filters': function() {
    ['filter-hostname', 'filter-severity', 'filter-date-from', 'filter-date-to'].forEach(function(id) {
      document.getElementById(id).value = '';
    });
    htmx.ajax('GET', '/api/scans?format=html&page=1', '#scan-table-body');
  },
});
