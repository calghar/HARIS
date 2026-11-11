(function() {
  const root = document.getElementById('scan-page');
  const scanId = root.dataset.scanId;
  const scanUrl = '/api/v1/scans/' + encodeURIComponent(scanId);
  const llmUrl = '/api/v1/llm';
  const TERMINAL = ['completed', 'failed', 'cancelled', 'incomplete'];
  let conversationId = null;
  let totalTokens = 0;

  const area = document.getElementById('chat-messages');
  const input = document.getElementById('ask-input');
  const backendSelect = document.getElementById('llm-backend');
  const askButton = document.getElementById('ask-btn');
  const meta = document.getElementById('chat-meta');

  // Reload when a polled running scan finishes
  document.body.addEventListener('htmx:afterRequest', function(e) {
    try {
      const data = JSON.parse(e.detail.xhr.responseText);
      if (TERMINAL.includes(data.status)) {
        globalThis.location.reload();
      }
    } catch (err) {
      console.error('Error parsing scan status response:', err);
    }
  });

  if (!area) return;

  const welcomeHtml = area.innerHTML;
  haris.fillBackends(backendSelect);

  function appendMessage(role, content) {
    const welcome = area.querySelector('.chat-welcome');
    if (welcome) welcome.remove();
    const bubble = document.createElement('div');
    bubble.className = role === 'user' ? 'chat-bubble-user' : 'chat-bubble-assistant';
    if (role === 'assistant') {
      haris.setMarkdown(bubble, content);
    } else {
      bubble.textContent = content;
    }
    area.appendChild(bubble);
    area.scrollTop = area.scrollHeight;
  }

  function showTyping() {
    const el = document.createElement('div');
    el.className = 'chat-bubble-assistant typing-indicator';
    el.id = 'typing-indicator';
    el.append(document.createElement('span'), document.createElement('span'), document.createElement('span'));
    area.appendChild(el);
    area.scrollTop = area.scrollHeight;
  }

  function hideTyping() {
    const el = document.getElementById('typing-indicator');
    if (el) el.remove();
  }

  function postJson(url, payload) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).then(function(r) { return r.json(); });
  }

  function submitQuestion(e) {
    if (e) e.preventDefault();
    const question = input.value.trim();
    if (!question) return;
    input.value = '';
    askButton.disabled = true;
    appendMessage('user', question);
    showTyping();

    const payload = { scan_id: scanId, question: question, backend: backendSelect.value };
    if (conversationId) payload.conversation_id = conversationId;
    postJson(llmUrl + '/chat', payload)
      .then(function(data) {
        hideTyping();
        askButton.disabled = false;
        if (data.error || data.detail) {
          appendMessage('assistant', 'Error: ' + (data.error || data.detail));
          return;
        }
        conversationId = data.conversation_id;
        totalTokens = data.total_tokens || 0;
        appendMessage('assistant', data.answer);
        meta.textContent = (data.model || '') + ' | ' + totalTokens + ' tokens';
        meta.style.display = 'block';
      })
      .catch(function(err) {
        hideTyping();
        askButton.disabled = false;
        appendMessage('assistant', 'Request failed: ' + err);
      });
  }

  function explainFinding(findingId) {
    document.querySelectorAll('.tab, .tab-content').forEach(function(t) { t.classList.remove('active'); });
    document.querySelector('[data-tab="tab-ask"]').classList.add('active');
    document.getElementById('tab-ask').classList.add('active');
    appendMessage('user', 'Explain finding ' + findingId);
    showTyping();
    postJson(llmUrl + '/explain', { scan_id: scanId, finding_id: findingId, backend: backendSelect.value })
      .then(function(data) {
        hideTyping();
        appendMessage('assistant', data.answer === undefined ? 'Error: ' + (data.error || data.detail) : data.answer);
      })
      .catch(function(err) {
        hideTyping();
        appendMessage('assistant', 'Request failed: ' + err);
      });
  }

  document.getElementById('ask-form').addEventListener('submit', submitQuestion);
  input.addEventListener('input', function() {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 100) + 'px';
  });

  haris.actions({
    'new-chat': function() {
      conversationId = null;
      totalTokens = 0;
      area.innerHTML = welcomeHtml;
      meta.style.display = 'none';
    },
    'ask-preset': function(el) {
      input.value = el.dataset.question;
      submitQuestion();
    },
    'explain-finding': function(el) { explainFinding(el.dataset.findingId); },
    'cancel-scan': function() {
      if (!confirm('Cancel this scan?')) return;
      fetch(scanUrl + '/cancel', { method: 'POST' })
        .then(async function(r) {
          if (r.ok) {
            globalThis.location.reload();
          } else {
            alert(await haris.errorMessage(r));
          }
        })
        .catch(function(err) { alert('Cancel failed: ' + err); });
    },
    'delete-scan': function() {
      if (!confirm('Delete this scan and all its reports? This cannot be undone.')) return;
      fetch(scanUrl, { method: 'DELETE' })
        .then(async function(r) {
          if (r.ok) {
            globalThis.location.href = '/scans';
          } else {
            alert(await haris.errorMessage(r));
          }
        })
        .catch(function(err) { alert('Delete failed: ' + err); });
    },
  });
})();
