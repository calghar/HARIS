haris.actions({
  'revoke-session': function(el) {
    if (!confirm('Revoke this session? The device will be signed out.')) return;
    const hash = el.dataset.tokenHash;
    fetch('/auth/profile/sessions/' + encodeURIComponent(hash), { method: 'DELETE' })
      .then(async function(r) {
        if (r.ok) {
          const row = document.getElementById('session-row-' + hash);
          if (row) row.remove();
        } else {
          alert((await haris.errorMessage(r)) || 'Revoke failed.');
        }
      })
      .catch(function() { alert('Request failed.'); });
  },
});
