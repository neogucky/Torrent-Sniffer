const $ = (selector) => document.querySelector(selector);
const status = (message = '') => { $('#status').textContent = message; };
let sources = [];
let jobs = [];
let adapters = [];
let editingSourceId = null;
let editingAdapterId = null;
let currentUser = null;
let needsSetup = false;

async function api(path, options = {}) {
  const response = await fetch(path, { headers: {'Content-Type': 'application/json'}, ...options });
  if (!response.ok) {
    const message = (await response.json().catch(() => ({}))).detail || 'Request failed';
    if (response.status === 401 && !path.startsWith('/api/auth/')) showAuth(false);
    throw new Error(message);
  }
  return response.status === 204 ? null : response.json();
}

function showAuth(setup) {
  needsSetup = setup; currentUser = null; $('#app').hidden = true; $('#account').hidden = true;
  $('#auth-title').textContent = setup ? 'Create the owner account' : 'Log in';
  $('#auth-copy').textContent = setup ? 'No account exists yet. This one-time setup creates the administrator.' : 'Use your Torrent Sniffer account.';
  $('#auth-confirm-wrap').hidden = !setup; $('#auth-submit').textContent = setup ? 'Create account' : 'Log in'; $('#auth-error').textContent = '';
  if (!$('#auth-dialog').open) $('#auth-dialog').showModal();
}

async function activateUser(user) {
  currentUser = user; $('#current-user').textContent = user.username; $('#account').hidden = false; $('#app').hidden = false;
  if ($('#auth-dialog').open) $('#auth-dialog').close(); await refreshAll();
}

async function initialiseApp() {
  try {
    const auth = await api('/api/auth/status');
    if (auth.user) await activateUser(auth.user); else showAuth(auth.needs_setup);
  } catch (error) { status(error.message); }
}

function sourceName(source) {
  try { return new URL(source.base_url).hostname; } catch { return source.base_url; }
}

async function refreshSources() {
  sources = await api('/api/sources');
  const select = $('#source-select'); const selected = select.value;
  select.replaceChildren(...sources.map(source => new Option(sourceName(source), source.id)));
  if (sources.some(source => String(source.id) === selected)) select.value = selected;
  const disabled = !sources.length;
  $('#edit-source').disabled = disabled; $('#delete-source').disabled = disabled; $('#queue-search').disabled = disabled;
}

async function refreshAdapters() {
  adapters = await api('/api/adapters');
}

function actionButton(label, action, job, className = '') {
  const button = document.createElement('button'); button.textContent = label; button.className = className;
  button.onclick = async () => {
    try { await api(`/api/jobs/${job.id}?action=${action}`, {method: 'PATCH'}); await refreshAll(); }
    catch (error) { status(error.message); }
  };
  return button;
}

async function deleteTask(job) {
  if (!confirm(`Remove task “${job.query}”? Found results will be kept.`)) return;
  try { await api(`/api/jobs/${job.id}`, {method: 'DELETE'}); await refreshAll(); }
  catch (error) { status(error.message); }
}

function populateActivePreview() {
  const list = $('#active-tasks'); list.replaceChildren();
  const visible = jobs.filter(job => job.state === 'running').slice(0, 4);
  for (const job of visible) {
    const item = document.createElement('div'); item.className = `mini-task ${job.state}`;
    const info = document.createElement('span'); info.textContent = `${sourceName(job)} · p${job.next_page}`;
    item.append(info);
    item.append(actionButton('■', 'stop', job, 'icon-button'));
    list.append(item);
  }
}

function taskCard(job) {
  const item = document.createElement('article');
  const heading = document.createElement('strong'); heading.textContent = `#${job.id} · ${job.query}`;
  const detail = document.createElement('p');
  detail.textContent = `${job.state} · ${sourceName(job)} · ${job.pages_crawled} page${job.pages_crawled === 1 ? '' : 's'} · ${job.results_found} unique saved · ${job.matches_seen} matches seen · next: page ${job.next_page} · wait: ${job.current_delay_seconds}s`;
  item.append(heading, detail);
  if (job.last_error) { const error = document.createElement('p'); error.className = 'error'; error.textContent = job.last_error; item.append(error); }
  const actions = document.createElement('div'); actions.className = 'job-actions';
  if (job.state === 'running') actions.append(actionButton('Stop', 'stop', job));
  if (job.state === 'stopped') actions.append(actionButton('Continue', 'continue', job), actionButton('Mark complete', 'complete', job));
  if (job.state === 'failed') actions.append(actionButton('Retry this page', 'retry', job), actionButton('Mark complete', 'complete', job));
  if (job.state !== 'running') { const remove = document.createElement('button'); remove.textContent = 'Remove'; remove.onclick = () => deleteTask(job); actions.append(remove); }
  const details = document.createElement('button'); details.textContent = 'Details'; details.onclick = () => showRequestDetails(job.id); actions.append(details);
  item.append(actions); return item;
}

async function refreshJobs() {
  jobs = await api('/api/jobs');
  $('#running-jobs').replaceChildren(...jobs.filter(job => job.state !== 'complete').map(taskCard));
  $('#completed-jobs').replaceChildren(...jobs.filter(job => job.state === 'complete').map(taskCard));
  populateActivePreview();
}

async function showRequestDetails(jobId) {
  try {
    const requests = await api(`/api/jobs/${jobId}/requests`);
    const panel = document.createElement('section'); panel.className = 'request-log';
    panel.innerHTML = `<div><h3>Request details · task #${jobId}</h3><button>Close</button></div>`;
    panel.querySelector('button').onclick = () => panel.remove();
    const list = document.createElement('div');
    for (const request of requests) {
      const entry = document.createElement('p'); const change = request.wait_adjustment_seconds ? ` (${request.wait_adjustment_seconds > 0 ? '+' : ''}${request.wait_adjustment_seconds}s)` : '';
      entry.textContent = `${request.request_type} · ${request.status}${request.page ? ` · page ${request.page}` : ''} · wait ${request.wait_before_seconds}s → ${request.effective_wait_seconds}s${change} · ${request.url}${request.error ? ` · ${request.error}` : ''}`;
      list.append(entry);
    }
    if (!requests.length) list.textContent = 'No requests have been made yet.';
    panel.append(list); document.body.append(panel);
  } catch (error) { status(error.message); }
}

async function refreshSummary() {
  const data = await api('/api/summary');
  $('#total-results').textContent = data.total_results; $('#total-crawls').textContent = data.total_crawls; $('#active-crawls').textContent = data.active_crawls || 0;
}

async function refreshAll() { await Promise.all([refreshAdapters(), refreshSources(), refreshJobs(), refreshSummary()]); }

async function searchLocal() {
  const rawQuery = $('#local-query').value.trim(); const list = $('#results');
  if (!rawQuery) { list.replaceChildren(); status(''); return; }
  const results = await api(`/api/results?q=${encodeURIComponent(rawQuery)}&include_description=${$('#include-description').checked}`);
  list.replaceChildren();
  for (const result of results) {
    const node = $('#result-template').content.cloneNode(true); const link = node.querySelector('.title'); link.href = result.details_url; link.textContent = result.title;
    node.querySelector('.metadata').textContent = [result.category, result.size, `↑ ${result.seeders ?? '—'}`, `↓ ${result.leechers ?? '—'}`].filter(Boolean).join(' · ');
    const magnet = node.querySelector('.magnet'); const fetchButton = node.querySelector('.fetch-magnet');
    const showMagnet = (link, button) => { magnet.href = link; magnet.textContent = 'Magnet link: open'; magnet.hidden = false; button?.remove(); };
    if (result.magnet_link) showMagnet(result.magnet_link, fetchButton);
    else { const button = fetchButton; button.onclick = async () => { const original = button.textContent; button.disabled = true; button.innerHTML = '<span class="spinner" aria-hidden="true"></span> Fetching…'; try { const data = await api(`/api/results/${result.id}/magnet`, {method: 'POST'}); if (data.magnet_link) { showMagnet(data.magnet_link, button); status('Magnet link fetched.'); } else { button.textContent = 'No magnet link found'; status('The detail page did not contain a magnet link.'); } } catch (error) { button.disabled = false; button.textContent = original; status(error.message); } }; }
    node.querySelector('.query').textContent = `Collected from “${result.remote_query}” · ${result.discovered_at}`; list.append(node);
  }
  status(`${results.length} locally matching result${results.length === 1 ? '' : 's'}.`);
}

function openSourceDialog(source = null) {
  editingSourceId = source?.id ?? null; $('#source-dialog-title').textContent = source ? 'Edit source' : 'Add source';
  const adapterSelect = $('#source-kind'); adapterSelect.replaceChildren(...adapters.map(adapter => new Option(adapter.label, adapter.id)));
  adapterSelect.value = source?.kind ?? adapters[0]?.id ?? ''; $('#source-url').value = source?.base_url ?? ''; $('#delay').value = source?.min_delay_seconds ?? 20;
  $('#add-adapter').hidden = !currentUser?.is_admin; $('#edit-adapter').hidden = !currentUser?.is_admin;
  $('#source-dialog').showModal();
}

const emptyAdapter = () => ({
  id: 'new-adapter', label: 'New adapter',
  search: {path_template: '/search/{query}/{page}/', query_encoding: 'percent'},
  pagination: {href_regex: ''},
  result: {required_link_href_contains: '', fields: {title: {}, details_url: {}}},
  magnet: {href_regex: ''}
});

async function openAdapterDialog(adapterId = null) {
  try {
    editingAdapterId = adapterId;
    const definition = adapterId ? await api(`/api/adapters/${adapterId}`) : emptyAdapter();
    $('#adapter-dialog-title').textContent = adapterId ? 'Edit adapter' : 'Add adapter';
    $('#adapter-json').value = JSON.stringify(definition, null, 2);
    $('#adapter-dialog').showModal();
  } catch (error) { status(error.message); }
}

$('#add-source').onclick = () => openSourceDialog();
$('#edit-source').onclick = () => openSourceDialog(sources.find(source => source.id === Number($('#source-select').value)));
$('#delete-source').onclick = async () => {
  const source = sources.find(item => item.id === Number($('#source-select').value)); if (!source || !confirm(`Delete ${sourceName(source)}? Tasks will be removed but found results stay.`)) return;
  try { await api(`/api/sources/${source.id}`, {method: 'DELETE'}); await refreshAll(); status('Source deleted; found results were retained.'); } catch (error) { status(error.message); }
};
$('#close-source-dialog').onclick = $('#cancel-source').onclick = () => $('#source-dialog').close();
$('#add-adapter').onclick = () => openAdapterDialog();
$('#edit-adapter').onclick = () => openAdapterDialog($('#source-kind').value);
$('#source-form').onsubmit = async (event) => {
  event.preventDefault(); const payload = {base_url: $('#source-url').value, kind: $('#source-kind').value, min_delay_seconds: Number($('#delay').value)};
  try { await api(editingSourceId ? `/api/sources/${editingSourceId}` : '/api/sources', {method: editingSourceId ? 'PUT' : 'POST', body: JSON.stringify(payload)}); $('#source-dialog').close(); await refreshAll(); status('Source saved.'); } catch (error) { status(error.message); }
};
$('#close-adapter-dialog').onclick = $('#cancel-adapter').onclick = () => $('#adapter-dialog').close();
$('#adapter-form').onsubmit = async (event) => {
  event.preventDefault();
  let definition;
  try { definition = JSON.parse($('#adapter-json').value); } catch { status('Adapter JSON is invalid.'); return; }
  try {
    const saved = await api(editingAdapterId ? `/api/adapters/${editingAdapterId}` : '/api/adapters', {method: editingAdapterId ? 'PUT' : 'POST', body: JSON.stringify({definition})});
    await refreshAdapters(); $('#source-kind').replaceChildren(...adapters.map(adapter => new Option(adapter.label, adapter.id))); $('#source-kind').value = saved.id;
    $('#adapter-dialog').close(); status('Adapter saved.');
  } catch (error) { status(error.message); }
};
$('#queue-search').onclick = async () => {
  try { await api('/api/jobs', {method: 'POST', body: JSON.stringify({source_id: Number($('#source-select').value), query: $('#remote-query').value})}); $('#remote-query').value = ''; await refreshAll(); status('Task started; requests will be paced.'); }
  catch (error) { status(error.message); }
};
$('#local-search').onclick = () => searchLocal().catch(error => status(error.message));
$('#local-query').addEventListener('keydown', event => { if (event.key === 'Enter') searchLocal().catch(error => status(error.message)); });
$('#auth-form').onsubmit = async (event) => {
  event.preventDefault(); const username = $('#auth-username').value; const password = $('#auth-password').value;
  if (needsSetup && password !== $('#auth-confirm').value) { $('#auth-error').textContent = 'Passwords do not match.'; return; }
  try { const user = await api(needsSetup ? '/api/auth/setup' : '/api/auth/login', {method: 'POST', body: JSON.stringify({username, password})}); await activateUser(user); }
  catch (error) { $('#auth-error').textContent = error.message; }
};
$('#auth-dialog').addEventListener('cancel', event => event.preventDefault());
$('#logout').onclick = async () => { try { await api('/api/auth/logout', {method: 'POST'}); showAuth(false); } catch (error) { status(error.message); } };
$('#open-settings').onclick = async () => {
  $('#settings-error').textContent = ''; $('#password-form').reset(); const management = $('#user-management'); management.hidden = !currentUser?.is_admin;
  try {
    if (currentUser?.is_admin) { const users = await api('/api/auth/users'); $('#user-list').replaceChildren(...users.map(user => { const item = document.createElement('p'); item.textContent = `${user.username}${user.is_admin ? ' · administrator' : ''}`; return item; })); }
    $('#settings-dialog').showModal();
  } catch (error) { status(error.message); }
};
$('#close-settings').onclick = () => $('#settings-dialog').close();
$('#password-form').onsubmit = async (event) => { event.preventDefault(); try { await api('/api/auth/password', {method: 'POST', body: JSON.stringify({current_password: $('#current-password').value, new_password: $('#new-password').value})}); $('#password-form').reset(); $('#settings-error').textContent = 'Password changed.'; } catch (error) { $('#settings-error').textContent = error.message; } };
$('#create-user-form').onsubmit = async (event) => { event.preventDefault(); try { await api('/api/auth/users', {method: 'POST', body: JSON.stringify({username: $('#new-username').value, password: $('#new-user-password').value})}); const users = await api('/api/auth/users'); $('#user-list').replaceChildren(...users.map(user => { const item = document.createElement('p'); item.textContent = `${user.username}${user.is_admin ? ' · administrator' : ''}`; return item; })); $('#create-user-form').reset(); $('#settings-error').textContent = 'User created.'; } catch (error) { $('#settings-error').textContent = error.message; } };
initialiseApp();
setInterval(() => { if (currentUser) refreshJobs().catch(() => {}); }, 5000);
