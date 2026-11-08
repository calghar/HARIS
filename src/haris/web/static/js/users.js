(function() {
  const byId = function(id) { return document.getElementById(id); };

  function send(url, method, params, failure) {
    const opts = { method: method };
    if (params) opts.body = new URLSearchParams(params);
    return fetch(url, opts)
      .then(async function(r) {
        if (r.ok) {
          globalThis.location.reload();
        } else {
          alert((await haris.errorMessage(r)) || failure);
        }
      })
      .catch(function() { alert('Request failed.'); });
  }

  byId('create-user-toggle').addEventListener('click', function() {
    byId('create-user-form').style.display = 'block';
    byId('create-user-toggle').style.display = 'none';
  });
  byId('create-user-cancel').addEventListener('click', function() {
    byId('create-user-form').style.display = 'none';
    byId('create-user-toggle').style.display = '';
  });

  haris.actions({
    'toggle-active': function(el) {
      const activate = el.dataset.active === 'true';
      if (!confirm('Are you sure you want to ' + (activate ? 'activate' : 'deactivate') + ' this user?')) return;
      send('/auth/users/' + encodeURIComponent(el.dataset.userId), 'PUT',
        { is_active: el.dataset.active }, 'Action failed.');
    },
    'change-role': function(el) {
      if (!confirm("Change this user's role to " + el.dataset.role + '?')) return;
      send('/auth/users/' + encodeURIComponent(el.dataset.userId), 'PUT',
        { role: el.dataset.role }, 'Action failed.');
    },
    'delete-user': function(el) {
      if (!confirm('Permanently delete user "' + el.dataset.email + '"? This cannot be undone.')) return;
      send('/auth/users/' + encodeURIComponent(el.dataset.userId), 'DELETE', null, 'Delete failed.');
    },
  });
})();
