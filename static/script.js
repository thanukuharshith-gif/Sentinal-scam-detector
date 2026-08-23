const tabs = document.querySelectorAll('.tab');
const urlPanel = document.getElementById('urlPanel');
const textPanel = document.getElementById('textPanel');
const urlInput = document.getElementById('urlInput');
const textInput = document.getElementById('textInput');
const textLabel = document.getElementById('textLabel');
const textHint = document.getElementById('textHint');
const result = document.getElementById('result');
let activeType = 'url';

const labels = {
  email: 'Paste email content (subject + body + headers if available)',
  message: 'Paste the message',
  call: 'Paste the call transcript or conversation notes'
};
const hints = {
  email: 'Include the subject and, if available, From/Reply-To information. Do not paste passwords or private account details.',
  message: 'Works with SMS, WhatsApp, Telegram, social-media messages and similar text.',
  call: 'For now, paste a transcript or notes. Voice-to-text can be added in Phase 3.'
};

for (const tab of tabs) {
  tab.addEventListener('click', () => {
    activeType = tab.dataset.type;
    tabs.forEach(t => t.classList.toggle('active', t === tab));
    urlPanel.classList.toggle('active', activeType === 'url');
    textPanel.classList.toggle('active', activeType !== 'url');
    if (activeType !== 'url') {
      textLabel.textContent = labels[activeType];
      textHint.textContent = hints[activeType];
      textInput.placeholder = activeType === 'call'
        ? 'Caller: I am calling from your bank...'
        : activeType === 'email'
          ? 'Subject: Your account needs verification...'
          : 'URGENT! Your account will be blocked...';
    }
    result.classList.add('hidden');
  });
}

document.getElementById('urlButton').addEventListener('click', analyzeURL);
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') analyzeURL(); });
document.getElementById('textButton').addEventListener('click', analyzeText);

async function analyzeURL() {
  const value = urlInput.value.trim();
  if (!value) return showError('Please enter a URL.');
  showLoading('Analyzing URL…');
  await post('/api/check-url', { url: value });
}

async function analyzeText() {
  const value = textInput.value.trim();
  if (!value) return showError('Please paste some content first.');
  showLoading('Analyzing content…');
  await post('/api/check-text', { text: value, source: activeType });
}

async function post(endpoint, payload) {
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    if (!response.ok) return showError(data.error || 'The server could not analyze this input.');
    renderResult(data);
  } catch (err) {
    showError('Could not connect to the Flask server. Make sure app.py is running.');
  }
}

function showLoading(message) {
  result.classList.remove('hidden');
  result.innerHTML = `<div class="loading"><div class="spinner"></div><h2>${escapeHTML(message)}</h2><p>Checking the supplied information…</p></div>`;
}

function showError(message) {
  result.classList.remove('hidden');
  result.innerHTML = `<div class="error"><h2>⚠️ Error</h2><p>${escapeHTML(message)}</p></div>`;
}

function renderResult(data) {
  result.classList.remove('hidden');
  const tone = data.score >= 80 ? 'critical' : data.score >= 60 ? 'high' : data.score >= 35 ? 'medium' : 'low';
  const reasons = (data.reasons || []).map(r => `<li>${escapeHTML(r)}</li>`).join('');
  const urls = (data.urls || []).map(u => `
    <div class="url-item">
      <strong>${escapeHTML(u.domain)}</strong>
      <span>${escapeHTML(u.result)} · ${u.score}/100</span>
    </div>`).join('');

  const reputation = data.reputation;
  let reputationHTML = '';
  if (reputation) {
    if (reputation.status === 'match') {
      const types = reputation.threats.flatMap(t => t.threat_types || []).join(', ');
      reputationHTML = `<div class="recommend danger"><strong>Threat intelligence:</strong> Google Safe Browsing reports a known threat${types ? ` (${escapeHTML(types)})` : ''}.</div>`;
    } else if (reputation.status === 'no_match') {
      reputationHTML = `<div class="recommend"><strong>Threat intelligence:</strong> No Google Safe Browsing match was found.</div>`;
    } else if (reputation.status === 'not_configured') {
      reputationHTML = `<div class="recommend"><strong>Threat intelligence:</strong> Not configured. Local heuristic analysis was used.</div>`;
    } else {
      reputationHTML = `<div class="recommend"><strong>Threat intelligence:</strong> Lookup unavailable; local heuristic analysis was still completed.</div>`;
    }
  }

  result.innerHTML = `
    <div class="result-head">
      <div><p class="eyebrow">Analysis complete</p><h2>${escapeHTML(data.result)}</h2><p>${data.domain ? escapeHTML(data.domain) : 'Content analysis'}</p></div>
      <div class="score ${tone}">${data.score}<small>/100</small></div>
    </div>
    <div class="meter ${tone}" style="--score:${data.score}%"><div></div></div>
    <h3>Why this score?</h3>
    <ul class="reasons">${reasons}</ul>
    <div class="recommend"><strong>What to do:</strong> ${escapeHTML(data.recommendation)}</div>
    ${reputationHTML}
    ${urls ? `<div class="url-list"><h3>URLs found in the content</h3>${urls}</div>` : ''}
    <p class="disclaimer">Risk scores are heuristic. A low score does not prove legitimacy, and a high score does not identify the attacker.</p>
  `;
  result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}
