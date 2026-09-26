// ============================================================
// APP STATE + IndexedDB (Target Workspace: targets, notes, file refs, settings)
// ============================================================

let DB;
let currentTargetId = null;
let currentPage = 'idor';
let currentTab = 'recon';
let searchQuery = '';
let lastTabByBug = {};
let editingItemId = null;
let masteryMap = {};
let allTargetsCache = [];

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('reconbook-db', 2);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('targets')) {
        db.createObjectStore('targets', { keyPath: 'id', autoIncrement: true });
      }
      if (!db.objectStoreNames.contains('items')) {
        const store = db.createObjectStore('items', { keyPath: 'id', autoIncrement: true });
        store.createIndex('targetId', 'targetId', { unique: false });
      }
      if (!db.objectStoreNames.contains('settings')) {
        db.createObjectStore('settings', { keyPath: 'key' });
      }
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror = (e) => reject(e);
  });
}

function dbAdd(storeName, value) {
  return new Promise((resolve, reject) => {
    const tx = DB.transaction(storeName, 'readwrite');
    const req = tx.objectStore(storeName).add(value);
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e);
  });
}

function dbPut(storeName, value) {
  return new Promise((resolve, reject) => {
    const tx = DB.transaction(storeName, 'readwrite');
    const req = tx.objectStore(storeName).put(value);
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e);
  });
}

function dbGetAll(storeName) {
  return new Promise((resolve, reject) => {
    const tx = DB.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).getAll();
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e);
  });
}

function dbGet(storeName, key) {
  return new Promise((resolve, reject) => {
    const tx = DB.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e);
  });
}

function dbDelete(storeName, id) {
  return new Promise((resolve, reject) => {
    const tx = DB.transaction(storeName, 'readwrite');
    const req = tx.objectStore(storeName).delete(id);
    req.onsuccess = () => resolve();
    req.onerror = (e) => reject(e);
  });
}

// ============================================================
// SIDEBAR
// ============================================================

const BUG_ORDER = ['idor', 'api', 'xss', 'bizlogic', 'race', 'ssrf'];
const STATUS_OPTIONS = ['to-test', 'in-progress', 'confirmed', 'reported', 'dead-end'];

function renderSidebar() {
  const nav = document.getElementById('navScroll');
  let html = '<div class="nav-group-label">Reference Library</div>';
  BUG_ORDER.forEach(id => {
    const b = BUGS[id];
    const active = (currentPage === id) ? 'active' : '';
    const mastered = masteryMap[id] ? '<span title="Mastered" style="margin-left:auto;color:var(--accent);font-size:12px">✓</span>' : '';
    html += `<div class="nav-item ${active}" data-page="${id}">
      <span class="dot ${b.severity}"></span>${b.name}${mastered}
    </div>`;
  });
  html += '<div class="nav-group-label">Field Guide</div>';
  html += `<div class="nav-item ${currentPage==='recon'?'active':''}" data-page="recon"><span class="dot low" style="background:var(--text-faint)"></span>Global Recon</div>`;
  html += `<div class="nav-item ${currentPage==='tools'?'active':''}" data-page="tools"><span class="dot low" style="background:var(--text-faint)"></span>Free Toolkit</div>`;
  html += `<div class="nav-item ${currentPage==='changelog'?'active':''}" data-page="changelog"><span class="dot low" style="background:var(--text-faint)"></span>What's New</div>`;
  html += '<div class="nav-group-label">Target Workspace</div>';
  html += `<div class="nav-item ${currentPage==='workspace'?'active':''}" data-page="workspace"><span class="dot low" style="background:var(--accent)"></span>Notes &amp; Files</div>`;
  nav.innerHTML = html;

  nav.querySelectorAll('.nav-item').forEach(el => {
    el.addEventListener('click', () => {
      currentPage = el.dataset.page;
      if (BUG_ORDER.includes(currentPage)) {
        currentTab = lastTabByBug[currentPage] || 'recon';
      }
      render();
    });
  });
}

// ============================================================
// BUG PAGE
// ============================================================

const TABS = [
  { id: 'recon', label: 'Recon' },
  { id: 'methodology', label: 'Method' },
  { id: 'payloads', label: 'Payloads' },
  { id: 'confirmation', label: 'Confirm' },
  { id: 'bypasses', label: 'Bypasses' },
  { id: 'impact', label: 'Impact' },
  { id: 'example', label: 'Example' },
  { id: 'tools', label: 'Tools' },
  { id: 'report', label: 'Report' },
];

async function renderBugPage(bug) {
  const main = document.getElementById('main');
  const tabsHtml = TABS.map(t => `<div class="tab ${currentTab===t.id?'active':''}" data-tab="${t.id}">${t.label}</div>`).join('');

  let linkedFilesHtml = '';
  if (currentTargetId) {
    const items = await dbGetAll('items');
    const files = items.filter(i => i.targetId === currentTargetId && i.type === 'file' && itemBugs(i).includes(bug.id));
    if (files.length) {
      linkedFilesHtml = `<div class="recon-block"><h4>Linked Files (current target)</h4>` +
        files.map(f => `<div class="file-item">${escapeHtml(f.filename)}<div class="meta">${escapeHtml(f.fileTag||'file')}${f.note ? ' — '+escapeHtml(f.note) : ''}</div></div>`).join('') +
        `</div>`;
    }
  }

  main.innerHTML = `
    <div class="case-header">
      <div class="case-meta">
        <span>${bug.tag}</span><span>·</span><span class="severity-tag ${bug.severity}">${bug.severity.toUpperCase()}</span>
      </div>
      <h2>${bug.name}</h2>
      <p>${bug.blurb}</p>
      <button class="btn secondary" id="masteryToggle" style="margin-top:12px">${masteryMap[bug.id] ? '✓ Mastered — click to unmark' : 'Mark as Mastered'}</button>
    </div>
    <div class="tabs">${tabsHtml}</div>
    <div id="tabContent"></div>
  `;

  document.getElementById('masteryToggle').addEventListener('click', async () => {
    masteryMap[bug.id] = !masteryMap[bug.id];
    await dbPut('settings', { key: 'mastery', value: masteryMap });
    renderBugPage(bug);
    renderSidebar();
  });

  renderTabContent(bug, linkedFilesHtml);

  main.querySelectorAll('.tab').forEach(el => {
    el.addEventListener('click', () => {
      currentTab = el.dataset.tab;
      lastTabByBug[bug.id] = currentTab;
      dbPut('settings', { key: 'lastTabByBug', value: lastTabByBug });
      renderBugPage(bug);
    });
  });
}

function renderTabContent(bug, linkedFilesHtml) {
  const el = document.getElementById('tabContent');
  if (!el) return;

  if (currentTab === 'payloads') {
    el.innerHTML = `<div class="panel active"><h3>Patterns &amp; Payloads</h3>` +
      bug.payloads.map(p => `<div class="payload-item">${escapeHtml(p)}</div>`).join('') +
      `</div>` + linkedFilesHtml;
    return;
  }
  if (currentTab === 'report') {
    el.innerHTML = `<div class="panel active"><h3>Report Template</h3><div class="report-box">${escapeHtml(bug.report)}</div></div>`;
    return;
  }
  if (currentTab === 'example') {
    el.innerHTML = `<div class="panel active"><h3>Real-World Example</h3><div class="report-box">${escapeHtml(bug.example)}</div></div>`;
    return;
  }
  if (currentTab === 'impact') {
    el.innerHTML = `<div class="panel active"><h3>Impact Tiers</h3><ul>${bug.impact.map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul></div>`;
    return;
  }

  const listMap = {
    recon: bug.recon,
    methodology: bug.methodology,
    confirmation: bug.confirmation,
    bypasses: bug.bypasses,
    tools: bug.tools,
  };
  const list = listMap[currentTab] || [];
  const heading = { recon: 'Recon', methodology: 'Methodology', confirmation: 'Confirmation Signals', bypasses: 'Bypasses & Edge Cases', tools: 'Free Tools' }[currentTab];
  el.innerHTML = `<div class="panel active"><h3>${heading}</h3><ul>${list.map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul></div>` +
    (currentTab === 'recon' ? linkedFilesHtml : '');
}

// ============================================================
// STATIC PAGES: Global Recon, Tools, Changelog
// ============================================================

function renderReconPage() {
  const main = document.getElementById('main');
  let html = `<div class="case-header">
      <div class="case-meta"><span>Field Guide</span></div>
      <h2>${GLOBAL_RECON.title}</h2>
      <p>${GLOBAL_RECON.subtitle}</p>
    </div>`;
  GLOBAL_RECON.sections.forEach(s => {
    html += `<div class="recon-block"><h4>${s.h}</h4><ul>${s.items.map(i=>`<li>${escapeHtml(i)}</li>`).join('')}</ul></div>`;
  });
  main.innerHTML = html;
}

function renderToolsPage() {
  const main = document.getElementById('main');
  let html = `<div class="case-header">
      <div class="case-meta"><span>Field Guide</span></div>
      <h2>${TOOLS.title}</h2>
      <p>${TOOLS.subtitle}</p>
    </div>`;
  TOOLS.groups.forEach(g => {
    html += `<div class="tool-group"><h4>${g.h}</h4><ul>${g.items.map(i=>`<li>${escapeHtml(i)}</li>`).join('')}</ul></div>`;
  });
  main.innerHTML = html;
}

function renderChangelogPage() {
  const main = document.getElementById('main');
  let html = `<div class="case-header">
      <div class="case-meta"><span>Field Guide</span></div>
      <h2>What's New</h2>
      <p>Version history for this app.</p>
    </div>`;
  CHANGELOG.forEach(v => {
    html += `<div class="recon-block"><h4>v${v.version} — ${v.date}</h4><ul>${v.changes.map(c=>`<li>${escapeHtml(c)}</li>`).join('')}</ul></div>`;
  });
  main.innerHTML = html;
}

// ============================================================
// SEARCH
// ============================================================

async function renderSearchPage(query) {
  const main = document.getElementById('main');
  const q = query.trim().toLowerCase();
  if (!q) {
    main.innerHTML = `<div class="case-header"><h2>Search</h2><p>Type in the sidebar search box to look across the Reference Library and your workspace.</p></div>`;
    return;
  }

  const libResults = [];
  BUG_ORDER.forEach(id => {
    const b = BUGS[id];
    const fields = { recon: b.recon, methodology: b.methodology, payloads: b.payloads, confirmation: b.confirmation, bypasses: b.bypasses, tools: b.tools, impact: b.impact };
    Object.entries(fields).forEach(([tab, arr]) => {
      arr.forEach(text => {
        if (text.toLowerCase().includes(q)) libResults.push({ bug: b, tab, text });
      });
    });
    if (b.example && b.example.toLowerCase().includes(q)) libResults.push({ bug: b, tab: 'example', text: b.example });
  });

  const items = await dbGetAll('items');
  const wsResults = items.filter(i => {
    const hay = [i.text, i.filename, i.note].filter(Boolean).join(' ').toLowerCase();
    return hay.includes(q);
  });

  let html = `<div class="case-header"><h2>Search: "${escapeHtml(query)}"</h2><p>${libResults.length} reference matches, ${wsResults.length} workspace matches.</p></div>`;

  if (libResults.length) {
    html += `<div class="recon-block"><h4>Reference Library</h4>`;
    libResults.slice(0, 40).forEach((r, idx) => {
      html += `<div class="file-item stagger-in" style="animation-delay:${idx*35}ms;cursor:pointer" data-goto="${r.bug.id}" data-tab="${r.tab}">
        <span class="severity-tag ${r.bug.severity}" style="margin-right:8px">${r.bug.name}</span>
        <span class="meta" style="font-family:var(--sans);color:var(--text-muted)">${escapeHtml(r.text.slice(0, 140))}${r.text.length>140?'…':''}</span>
      </div>`;
    });
    html += `</div>`;
  }

  if (wsResults.length) {
    html += `<div class="recon-block"><h4>Workspace</h4>`;
    wsResults.forEach((i, idx) => {
      html += `<div class="${i.type==='note'?'note-item':'file-item'} stagger-in" style="animation-delay:${idx*35}ms">${escapeHtml(i.text || i.filename)}<div class="meta">${escapeHtml(itemBugs(i).join(', ') || 'general')}${i.status?' · '+escapeHtml(i.status):''}</div></div>`;
    });
    html += `</div>`;
  }

  if (!libResults.length && !wsResults.length) {
    html += `<div class="empty-state">No matches.</div>`;
  }

  main.innerHTML = html;
  main.querySelectorAll('[data-goto]').forEach(el => {
    el.addEventListener('click', () => {
      currentPage = el.dataset.goto;
      currentTab = el.dataset.tab;
      lastTabByBug[currentPage] = currentTab;
      render();
    });
  });
}

// ============================================================
// WORKSPACE PAGE
// ============================================================

function flashSuccess(el) {
  if (!el) return;
  el.classList.add('flash-success');
  setTimeout(() => el.classList.remove('flash-success'), 500);
}

function itemBugs(item) {
  if (Array.isArray(item.linkedBugs)) return item.linkedBugs;
  if (item.linkedBug) return [item.linkedBug];
  return [];
}

function bugCheckboxes(name, selected) {
  selected = selected || [];
  const opts = BUG_ORDER.map(id => `<label style="display:inline-flex;align-items:center;gap:4px;margin:0 10px 6px 0;font-size:12.5px;color:var(--text-muted)">
      <input type="checkbox" name="${name}" value="${id}" ${selected.includes(id)?'checked':''}> ${BUGS[id].name}
    </label>`).join('');
  const general = `<label style="display:inline-flex;align-items:center;gap:4px;margin:0 10px 6px 0;font-size:12.5px;color:var(--text-muted)">
      <input type="checkbox" name="${name}" value="general" ${selected.includes('general')?'checked':''}> General
    </label>`;
  return `<div class="ws-form" style="flex-wrap:wrap">${opts}${general}</div>`;
}

function statusOptionsHtml(selected) {
  return STATUS_OPTIONS.map(s => `<option value="${s}" ${selected===s?'selected':''}>${s}</option>`).join('');
}

async function renderWorkspacePage() {
  const main = document.getElementById('main');
  const targets = await dbGetAll('targets');
  const target = targets.find(t => t.id === currentTargetId);

  if (!target) {
    main.innerHTML = `<div class="case-header">
      <div class="case-meta"><span>Target Workspace</span></div>
      <h2>No target selected</h2>
      <p>Create a target from the dropdown at the top of the sidebar to start logging recon notes and files.</p>
    </div>`;
    return;
  }

  const items = await dbGetAll('items');
  const targetItems = items.filter(i => i.targetId === currentTargetId).sort((a,b)=>b.id-a.id);
  const notes = targetItems.filter(i => i.type === 'note');
  const files = targetItems.filter(i => i.type === 'file');

  main.innerHTML = `
    <div class="case-header">
      <div class="case-meta"><span>Target Workspace</span></div>
      <h2>${escapeHtml(target.name)}</h2>
      <p>Notes and file references for this target. Files stay as pointers — actual file contents live on your machine.</p>
    </div>

    <div class="ws-section">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
        <h3 style="margin:0">Backup</h3>
        <div style="display:flex;gap:8px">
          <button class="btn secondary" id="exportBtn">Export all data (JSON)</button>
          <label class="btn secondary" style="cursor:pointer">Import backup<input type="file" id="importFile" accept="application/json" style="display:none"></label>
        </div>
      </div>
    </div>

    <div class="ws-section">
      <h3>Add a note</h3>
      <div class="ws-form">
        <textarea id="noteText" placeholder="What did you find / what are you testing next?"></textarea>
      </div>
      ${bugCheckboxes('noteBugs')}
      <div class="ws-form">
        <select id="noteStatus">${statusOptionsHtml('to-test')}</select>
        <button class="btn" id="addNoteBtn">Save note</button>
      </div>
    </div>

    <div class="ws-section">
      <h3>Notes (${notes.length})</h3>
      <div id="notesList">${notes.length ? notes.map(n => renderNoteItem(n)).join('') : '<div class="empty-state">No notes yet.</div>'}</div>
    </div>

    <div class="ws-section">
      <h3>Add a file reference</h3>
      <div class="ws-form">
        <input type="text" id="fileName" placeholder="e.g. endpoints.txt, burp-export.xml, screenshot-webhook.png">
      </div>
      <div class="ws-form">
        <select id="fileTag">
          <option value="subdomains">Subdomains</option>
          <option value="endpoints">Endpoints</option>
          <option value="js">JS dump</option>
          <option value="screenshot">Screenshot</option>
          <option value="export">Burp/ZAP export</option>
          <option value="notes">Notes file</option>
        </select>
        <input type="text" id="fileNote" placeholder="Optional note (where this came from / what it shows)">
      </div>
      ${bugCheckboxes('fileBugs')}
      <div class="ws-form">
        <button class="btn" id="addFileBtn">Save file reference</button>
      </div>
    </div>

    <div class="ws-section">
      <h3>File references (${files.length})</h3>
      <div id="filesList">${files.length ? files.map(f => renderFileItem(f)).join('') : '<div class="empty-state">No files linked yet.</div>'}</div>
    </div>
  `;

  document.getElementById('addNoteBtn').addEventListener('click', async (e) => {
    const text = document.getElementById('noteText').value.trim();
    if (!text) return;
    const linkedBugs = Array.from(document.querySelectorAll('input[name=noteBugs]:checked')).map(c => c.value);
    const status = document.getElementById('noteStatus').value;
    await dbAdd('items', { targetId: currentTargetId, type: 'note', text, linkedBugs, status });
    flashSuccess(e.target);
    renderWorkspacePage();
  });

  document.getElementById('addFileBtn').addEventListener('click', async (e) => {
    const filename = document.getElementById('fileName').value.trim();
    if (!filename) return;
    const fileTag = document.getElementById('fileTag').value;
    const note = document.getElementById('fileNote').value.trim();
    const linkedBugs = Array.from(document.querySelectorAll('input[name=fileBugs]:checked')).map(c => c.value);
    await dbAdd('items', { targetId: currentTargetId, type: 'file', filename, fileTag, linkedBugs, note });
    flashSuccess(e.target);
    renderWorkspacePage();
  });

  document.getElementById('exportBtn').addEventListener('click', exportBackup);
  document.getElementById('importFile').addEventListener('change', importBackup);

  bindWorkspaceItemEvents();
}

function renderNoteItem(n) {
  if (editingItemId === n.id) {
    return `<div class="note-item" data-edit-form="${n.id}">
      <textarea id="edit-text-${n.id}" style="width:100%;min-height:60px;background:var(--panel-raised);border:1px solid var(--border);color:var(--text);border-radius:4px;padding:8px;font-family:var(--sans);font-size:13px">${escapeHtml(n.text)}</textarea>
      ${bugCheckboxes('editBugs-'+n.id, itemBugs(n))}
      <div class="ws-form">
        <select id="edit-status-${n.id}">${statusOptionsHtml(n.status)}</select>
        <button class="btn" data-save-note="${n.id}">Save</button>
        <button class="btn secondary" data-cancel-edit>Cancel</button>
      </div>
    </div>`;
  }
  return `<div class="note-item">
    ${escapeHtml(n.text)}
    <div class="meta">
      <span class="tags">${itemBugs(n).map(id => `<span>${escapeHtml(id==='general'?'general':BUGS[id].name)}</span>`).join('') || '<span>general</span>'}</span>
      <span style="color:var(--accent)">${escapeHtml(n.status||'to-test')}</span>
      <span data-edit="${n.id}" style="cursor:pointer;float:right;margin-left:10px">edit</span>
      <span data-del="${n.id}" style="cursor:pointer;float:right;color:var(--text-faint)">remove</span>
    </div>
  </div>`;
}

function renderFileItem(f) {
  if (editingItemId === f.id) {
    return `<div class="file-item" data-edit-form="${f.id}">
      <input type="text" id="edit-filename-${f.id}" value="${escapeHtml(f.filename)}" style="width:100%;background:var(--panel-raised);border:1px solid var(--border);color:var(--text);border-radius:4px;padding:7px;font-family:var(--sans);font-size:13px;margin-bottom:8px">
      <input type="text" id="edit-note-${f.id}" value="${escapeHtml(f.note||'')}" placeholder="Note" style="width:100%;background:var(--panel-raised);border:1px solid var(--border);color:var(--text);border-radius:4px;padding:7px;font-family:var(--sans);font-size:13px;margin-bottom:8px">
      ${bugCheckboxes('editFileBugs-'+f.id, itemBugs(f))}
      <div class="ws-form">
        <button class="btn" data-save-file="${f.id}">Save</button>
        <button class="btn secondary" data-cancel-edit>Cancel</button>
      </div>
    </div>`;
  }
  return `<div class="file-item">
    ${escapeHtml(f.filename)}
    <div class="meta">
      <span class="tags"><span>${escapeHtml(f.fileTag)}</span>${itemBugs(f).map(id => `<span>${escapeHtml(id==='general'?'general':BUGS[id].name)}</span>`).join('')}</span>
      ${f.note ? '— '+escapeHtml(f.note) : ''}
      <span data-edit="${f.id}" style="cursor:pointer;float:right;margin-left:10px">edit</span>
      <span data-del="${f.id}" style="cursor:pointer;float:right;color:var(--text-faint)">remove</span>
    </div>
  </div>`;
}

function bindWorkspaceItemEvents() {
  const main = document.getElementById('main');

  main.querySelectorAll('[data-del]').forEach(el => {
    el.addEventListener('click', async () => {
      await dbDelete('items', Number(el.dataset.del));
      renderWorkspacePage();
    });
  });

  main.querySelectorAll('[data-edit]').forEach(el => {
    el.addEventListener('click', () => {
      editingItemId = Number(el.dataset.edit);
      renderWorkspacePage();
    });
  });

  main.querySelectorAll('[data-cancel-edit]').forEach(el => {
    el.addEventListener('click', () => {
      editingItemId = null;
      renderWorkspacePage();
    });
  });

  main.querySelectorAll('[data-save-note]').forEach(el => {
    el.addEventListener('click', async () => {
      const id = Number(el.dataset.saveNote);
      const items = await dbGetAll('items');
      const item = items.find(i => i.id === id);
      item.text = document.getElementById('edit-text-'+id).value.trim();
      item.status = document.getElementById('edit-status-'+id).value;
      item.linkedBugs = Array.from(document.querySelectorAll(`input[name=editBugs-${id}]:checked`)).map(c => c.value);
      delete item.linkedBug;
      await dbPut('items', item);
      editingItemId = null;
      renderWorkspacePage();
    });
  });

  main.querySelectorAll('[data-save-file]').forEach(el => {
    el.addEventListener('click', async () => {
      const id = Number(el.dataset.saveFile);
      const items = await dbGetAll('items');
      const item = items.find(i => i.id === id);
      item.filename = document.getElementById('edit-filename-'+id).value.trim();
      item.note = document.getElementById('edit-note-'+id).value.trim();
      item.linkedBugs = Array.from(document.querySelectorAll(`input[name=editFileBugs-${id}]:checked`)).map(c => c.value);
      delete item.linkedBug;
      await dbPut('items', item);
      editingItemId = null;
      renderWorkspacePage();
    });
  });
}

// ============================================================
// BACKUP / RESTORE
// ============================================================

async function exportBackup() {
  const targets = await dbGetAll('targets');
  const items = await dbGetAll('items');
  const data = { exportedAt: new Date().toISOString(), targets, items };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `casefile-backup-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function importBackup(e) {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    if (!data.targets || !data.items) throw new Error('Invalid backup file');
    if (!confirm(`Import ${data.targets.length} target(s) and ${data.items.length} item(s)? This adds to your existing data (won't overwrite).`)) return;

    const idMap = {};
    for (const t of data.targets) {
      const oldId = t.id;
      delete t.id;
      const newId = await dbAdd('targets', t);
      idMap[oldId] = newId;
    }
    for (const i of data.items) {
      delete i.id;
      i.targetId = idMap[i.targetId] || i.targetId;
      await dbAdd('items', i);
    }
    await renderTargetSelector();
    alert('Import complete.');
    renderWorkspacePage();
  } catch (err) {
    alert('Could not import that file: ' + err.message);
  }
}

// ============================================================
// TARGET SELECTOR
// ============================================================

async function renderTargetSelector(filterText) {
  const targets = await dbGetAll('targets');
  allTargetsCache = targets;
  const select = document.getElementById('targetSelect');
  const filtered = filterText
    ? targets.filter(t => t.name.toLowerCase().includes(filterText.toLowerCase()))
    : targets;
  select.innerHTML = filtered.map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join('');
  if (targets.length && !currentTargetId) {
    currentTargetId = targets[0].id;
  }
  if (currentTargetId && filtered.some(t => t.id === currentTargetId)) select.value = currentTargetId;

  select.onchange = () => {
    currentTargetId = Number(select.value);
    if (currentPage === 'workspace') render();
  };
}

document.getElementById('targetFilter').addEventListener('input', (e) => {
  renderTargetSelector(e.target.value);
});

document.getElementById('newTargetBtn').addEventListener('click', async () => {
  const name = prompt('Target / program name:');
  if (!name || !name.trim()) return;
  const id = await dbAdd('targets', { name: name.trim() });
  currentTargetId = id;
  await renderTargetSelector();
  currentPage = 'workspace';
  render();
});

document.getElementById('globalSearch').addEventListener('input', (e) => {
  searchQuery = e.target.value;
  currentPage = 'search';
  render();
});

// ============================================================
// ROUTER
// ============================================================

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

async function render() {
  renderSidebar();
  if (currentPage === 'recon') return renderReconPage();
  if (currentPage === 'tools') return renderToolsPage();
  if (currentPage === 'changelog') return renderChangelogPage();
  if (currentPage === 'search') return renderSearchPage(searchQuery);
  if (currentPage === 'workspace') return renderWorkspacePage();
  const bug = BUGS[currentPage];
  if (bug) return renderBugPage(bug);
}

(async function init() {
  DB = await openDB();
  const savedTabs = await dbGet('settings', 'lastTabByBug');
  if (savedTabs && savedTabs.value) lastTabByBug = savedTabs.value;
  const savedMastery = await dbGet('settings', 'mastery');
  if (savedMastery && savedMastery.value) masteryMap = savedMastery.value;
  await renderTargetSelector();
  render();
})();
