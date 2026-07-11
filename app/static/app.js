const $ = (selector) => document.querySelector(selector);
const status = (message = '') => { $('#status').textContent = message; };
let sources = [];
let jobs = [];
let adapters = [];
let editingSourceId = null;
let editingAdapterId = null;
let editingUserId = null;
let currentUser = null;
let needsSetup = false;
let qbittorrent = {configured: false, locations: []};

async function api(path, options = {}) {
  const response = await fetch(path, { headers: {'Content-Type': 'application/json'}, ...options });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const message = Array.isArray(payload.detail) ? payload.detail.map(item => item.msg || 'Invalid value').join('; ') : (payload.detail || 'Request failed');
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

async function refreshQbittorrent() { qbittorrent = await api('/api/qbittorrent'); }

async function refreshAll() { await Promise.all([refreshAdapters(), refreshSources(), refreshJobs(), refreshSummary(), refreshQbittorrent()]); }

async function searchLocal() {
  const rawQuery = $('#local-query').value.trim(); const list = $('#results');
  const ranges = {
    all: [0, null], small: [0, 4], 'movie-standard': [4, 10], 'movie-large': [8, 16], 'movie-huge': [16, null],
    'series-compact': [10, 30], 'series-standard': [20, 50], 'series-large': [50, null]
  };
  let [minGb, maxGb] = ranges[$('#size-filter').value] || [0, null];
  if ($('#size-filter').value === 'custom') {
    minGb = Number($('#min-size-gb').value || 0); const rawMax = $('#max-size-gb').value;
    maxGb = rawMax === '' ? null : Number(rawMax);
  }
  if (minGb < 0 || (maxGb !== null && (maxGb < 0 || maxGb < minGb))) { status('Enter a valid custom size range.'); return; }
  const gib = 1024 ** 3;
  const params = new URLSearchParams({q: rawQuery, include_description: $('#include-description').checked, min_size_bytes: String(Math.round(minGb * gib)), min_seeders: $('#seeder-filter').value, sort: $('#sort-results').value});
  if (maxGb !== null) params.set('max_size_bytes', String(Math.round(maxGb * gib)));
  const results = await api(`/api/results?${params}`);
  list.replaceChildren();
  for (const result of results) {
    const node = $('#result-template').content.cloneNode(true); const link = node.querySelector('.title'); link.href = result.details_url; link.textContent = result.title; link.title = result.title;
    node.querySelector('.metadata').textContent = [result.category, result.size, `↑ ${result.seeders ?? '—'}`, `↓ ${result.leechers ?? '—'}`, result.torrent_created_at ? `torrent date ${result.torrent_created_at}` : 'torrent date unknown'].filter(Boolean).join(' · ');
    const magnet = node.querySelector('.magnet'); const fetchButton = node.querySelector('.fetch-magnet');
    const qbitAction = node.querySelector('.qbit-action'); const locationSelect = qbitAction.querySelector('select');
    const showQbittorrent = () => {
      if (!qbittorrent.configured) return;
      qbitAction.hidden = false; locationSelect.replaceChildren(...qbittorrent.locations.map(location => new Option(location.label, location.label)));
      qbitAction.querySelector('.confirm-qbit').onclick = async () => {
        const button = qbitAction.querySelector('.confirm-qbit'); button.disabled = true; button.innerHTML = '<span class="spinner" aria-hidden="true"></span> Downloading…';
        try { await api(`/api/results/${result.id}/qbittorrent`, {method: 'POST', body: JSON.stringify({location_label: locationSelect.value})}); button.textContent = 'Downloaded'; status(`Sent to qBittorrent (${locationSelect.value}).`); }
        catch (error) { button.disabled = false; button.textContent = 'Download'; status(error.message); }
      };
    };
    const showMagnet = (magnetLink, button) => { magnet.href = magnetLink; magnet.hidden = false; button?.remove(); };
    showQbittorrent();
    if (qbittorrent.configured) fetchButton.remove();
    else if (result.magnet_link) showMagnet(result.magnet_link, fetchButton);
    else { const button = fetchButton; button.onclick = async () => { const original = button.textContent; button.disabled = true; button.innerHTML = '<span class="spinner" aria-hidden="true"></span> Fetching…'; try { const data = await api(`/api/results/${result.id}/magnet`, {method: 'POST'}); if (data.magnet_link) { showMagnet(data.magnet_link, button); status('Magnet link fetched.'); } else { button.textContent = 'No magnet link found'; status('The detail page did not contain a magnet link.'); } } catch (error) { button.disabled = false; button.textContent = original; status(error.message); } }; }
    node.querySelector('.query').textContent = `Collected from “${result.remote_query}” · ${result.discovered_at}`; list.append(node);
  }
  $('#result-tools').hidden = !results.length;
  updateFilterLabels();
  status(`${results.length} locally matching result${results.length === 1 ? '' : 's'}.`);
}

function updateFilterLabels() {
  const size = $('#size-filter'); const seeders = $('#seeder-filter');
  if (size.value === 'all') $('#size-summary').textContent = 'Size';
  else if (size.value === 'custom') {
    const min = $('#min-size-gb').value || '0'; const max = $('#max-size-gb').value;
    $('#size-summary').textContent = `Size: ${min}${max ? `–${max}` : '+'} GB`;
  } else $('#size-summary').textContent = `Size: ${size.options[size.selectedIndex].text}`;
  $('#seeder-summary').textContent = seeders.value === '0' ? 'Availability' : `Availability: ${seeders.options[seeders.selectedIndex].text}`;
}

function refreshFilteredResults() { if ($('#results').childElementCount) searchLocal().catch(error => status(error.message)); }

function openCustomSizeDialog() {
  $('#custom-size-error').textContent = ''; $('#custom-size-dialog').showModal();
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
function closeFilter(control) { control.closest('details').open = false; }
$('#size-filter').onchange = () => { if ($('#size-filter').value === 'custom') openCustomSizeDialog(); else { closeFilter($('#size-filter')); refreshFilteredResults(); } };
$('#seeder-filter').onchange = () => { closeFilter($('#seeder-filter')); refreshFilteredResults(); };
$('#sort-results').onchange = refreshFilteredResults;
$('#clear-size').onclick = () => { $('#size-filter').value = 'all'; $('#min-size-gb').value = ''; $('#max-size-gb').value = ''; closeFilter($('#size-filter')); refreshFilteredResults(); };
$('#clear-seeders').onclick = () => { $('#seeder-filter').value = '0'; closeFilter($('#seeder-filter')); refreshFilteredResults(); };
$('#close-custom-size').onclick = $('#cancel-custom-size').onclick = () => { if (!$('#min-size-gb').value && !$('#max-size-gb').value) $('#size-filter').value = 'all'; $('#custom-size-dialog').close(); updateFilterLabels(); };
$('#custom-size-form').onsubmit = (event) => {
  event.preventDefault(); const min = Number($('#min-size-gb').value || 0); const maxRaw = $('#max-size-gb').value; const max = maxRaw === '' ? null : Number(maxRaw);
  if (min < 0 || (max !== null && (max < 0 || max < min))) { $('#custom-size-error').textContent = 'Enter a valid size range.'; return; }
  $('#size-filter').value = 'custom'; $('#custom-size-dialog').close(); closeFilter($('#size-filter')); refreshFilteredResults();
};
$('#auth-form').onsubmit = async (event) => {
  event.preventDefault(); const username = $('#auth-username').value; const password = $('#auth-password').value;
  if (needsSetup && password !== $('#auth-confirm').value) { $('#auth-error').textContent = 'Passwords do not match.'; return; }
  try { const user = await api(needsSetup ? '/api/auth/setup' : '/api/auth/login', {method: 'POST', body: JSON.stringify({username, password})}); await activateUser(user); }
  catch (error) { $('#auth-error').textContent = error.message; }
};
$('#auth-dialog').addEventListener('cancel', event => event.preventDefault());
$('#logout').onclick = async () => { try { await api('/api/auth/logout', {method: 'POST'}); showAuth(false); } catch (error) { status(error.message); } };
function addQbittorrentLocation(location = {label: '', path: ''}) {
  const row = document.createElement('div'); row.className = 'qbit-location-row';
  const label = document.createElement('input'); label.placeholder = 'Label'; label.value = location.label;
  const path = document.createElement('input'); path.placeholder = 'Path in qBittorrent container'; path.value = location.path;
  const remove = document.createElement('button'); remove.type = 'button'; remove.textContent = 'Remove'; remove.onclick = () => row.remove();
  row.append(label, path, remove); $('#qbit-locations').append(row);
}

function renderQbittorrentLocations(locations) {
  $('#qbit-locations').replaceChildren(); (locations.length ? locations : [{label: '', path: ''}]).forEach(addQbittorrentLocation);
}

async function loadUsers() {
  const users = await api('/api/auth/users');
  const list = $('#user-list'); list.replaceChildren();
  for (const user of users) {
    const item = document.createElement('div'); item.className = 'user-row';
    const label = document.createElement('span'); label.textContent = `${user.username} · ${user.group}`;
    const actions = document.createElement('div'); actions.className = 'user-actions';
    const edit = document.createElement('button'); edit.type = 'button'; edit.textContent = 'Edit'; edit.onclick = () => openUserDialog(user);
    const remove = document.createElement('button'); remove.type = 'button'; remove.textContent = 'Remove'; remove.disabled = user.id === currentUser.id;
    remove.title = remove.disabled ? 'You cannot remove your own account' : '';
    remove.onclick = () => removeUser(user);
    actions.append(edit, remove); item.append(label, actions); list.append(item);
  }
}

function openUserDialog(user = null) {
  editingUserId = user?.id ?? null;
  $('#user-dialog-title').textContent = user ? `Edit ${user.username}` : 'Add user';
  $('#user-username').value = user?.username ?? ''; $('#user-group').value = user?.group ?? 'user';
  $('#user-password').value = ''; $('#user-password').required = !user; $('#user-password-hint').hidden = !user;
  $('#user-error').textContent = ''; $('#user-dialog').showModal();
}

async function removeUser(user) {
  if (!confirm(`Remove user “${user.username}”?`)) return;
  try { await api(`/api/auth/users/${user.id}`, {method: 'DELETE'}); await loadUsers(); $('#settings-error').textContent = 'User removed.'; }
  catch (error) { $('#settings-error').textContent = error.message; }
}

function renderQbittorrentSummary() {
  $('#configure-qbit').textContent = qbittorrent.configured ? 'Edit configuration' : 'Configure qBittorrent';
  $('#qbit-status').textContent = qbittorrent.configured
    ? `Configured: ${qbittorrent.base_url} · ${qbittorrent.locations.length} file location${qbittorrent.locations.length === 1 ? '' : 's'}`
    : 'No qBittorrent integration configured.';
}

async function openQbittorrentDialog() {
  try {
    await refreshQbittorrent();
    $('#qbit-url').value = qbittorrent.base_url || ''; $('#qbit-api-key').value = '';
    $('#qbit-api-key').placeholder = qbittorrent.configured ? 'Leave blank to keep existing key' : 'Required';
    $('#remove-qbit').hidden = !qbittorrent.configured; $('#qbit-error').textContent = '';
    renderQbittorrentLocations(qbittorrent.locations || []); $('#qbit-dialog').showModal();
  } catch (error) { $('#settings-error').textContent = error.message; }
}

$('#open-settings').onclick = async () => {
  $('#settings-error').textContent = ''; $('#password-form').reset(); const management = $('#user-management'); const qbitManagement = $('#qbit-management'); management.hidden = !currentUser?.is_admin; qbitManagement.hidden = !currentUser?.is_admin;
  try {
    if (currentUser?.is_admin) { await loadUsers(); await refreshQbittorrent(); renderQbittorrentSummary(); }
    $('#settings-dialog').showModal();
  } catch (error) { status(error.message); }
};
$('#close-settings').onclick = () => $('#settings-dialog').close();
$('#password-form').onsubmit = async (event) => { event.preventDefault(); if ($('#new-password').value !== $('#confirm-new-password').value) { $('#settings-error').textContent = 'New passwords do not match.'; return; } try { await api('/api/auth/password', {method: 'POST', body: JSON.stringify({new_password: $('#new-password').value})}); $('#password-form').reset(); $('#settings-error').textContent = 'Password changed.'; } catch (error) { $('#settings-error').textContent = error.message; } };
$('#add-user').onclick = () => openUserDialog();
$('#close-user-dialog').onclick = $('#cancel-user').onclick = () => $('#user-dialog').close();
$('#user-form').onsubmit = async (event) => {
  event.preventDefault(); const password = $('#user-password').value;
  const payload = {username: $('#user-username').value, group: $('#user-group').value};
  if (password) payload.password = password;
  try {
    await api(editingUserId ? `/api/auth/users/${editingUserId}` : '/api/auth/users', {method: editingUserId ? 'PUT' : 'POST', body: JSON.stringify({...payload, ...(editingUserId ? {} : {password})})});
    $('#user-dialog').close(); await loadUsers(); $('#settings-error').textContent = editingUserId ? 'User updated.' : 'User created.';
  } catch (error) { $('#user-error').textContent = error.message; }
};
$('#configure-qbit').onclick = () => openQbittorrentDialog();
$('#close-qbit-dialog').onclick = $('#cancel-qbit').onclick = () => $('#qbit-dialog').close();
$('#add-qbit-location').onclick = () => addQbittorrentLocation();
$('#qbit-form').onsubmit = async (event) => {
  event.preventDefault(); const locations = [...document.querySelectorAll('#qbit-locations .qbit-location-row')].map(row => ({label: row.children[0].value, path: row.children[1].value}));
  try { await api('/api/qbittorrent', {method: 'PUT', body: JSON.stringify({base_url: $('#qbit-url').value, api_key: $('#qbit-api-key').value || null, locations})}); await refreshQbittorrent(); renderQbittorrentSummary(); $('#qbit-dialog').close(); $('#settings-error').textContent = 'qBittorrent integration saved.'; }
  catch (error) { $('#qbit-error').textContent = error.message; }
};
$('#remove-qbit').onclick = async () => { if (!confirm('Disable the qBittorrent integration?')) return; try { await api('/api/qbittorrent', {method: 'DELETE'}); await refreshQbittorrent(); renderQbittorrentSummary(); $('#qbit-dialog').close(); $('#settings-error').textContent = 'qBittorrent integration disabled.'; } catch (error) { $('#qbit-error').textContent = error.message; } };
initialiseApp();
setInterval(() => { if (currentUser) refreshJobs().catch(() => {}); }, 5000);
