// ============================================================
// APP STATE + IndexedDB (Target Workspace: targets, notes, file refs)
// ============================================================

let DB;
let currentTargetId = null;
let currentPage = 'idor';
let currentTab = 'recon';

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('reconbook-db', 1);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('targets')) {
        db.createObjectStore('targets', { keyPath: 'id', autoIncrement: true });
      }
      if (!db.objectStoreNames.contains('items')) {
        const store = db.createObjectStore('items', { keyPath: 'id', autoIncrement: true });
        store.createIndex('targetId', 'targetId', { unique: false });
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

function dbGetAll(storeName) {
  return new Promise((resolve, reject) => {
    const tx = DB.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).getAll();
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e);
  });
}

function dbGetByIndex(storeName, indexName, value) {
  return new Promise((resolve, reject) => {
    const tx = DB.transaction(storeName, 'readonly');
    const idx = tx.objectStore(storeName).index(indexName);
    const req = idx.getAll(value);
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

function renderSidebar() {
  const nav = document.getElementById('navScroll');
  let html = '<div class="nav-group-label">Reference Library</div>';
  BUG_ORDER.forEach(id => {
    const b = BUGS[id];
    const active = (currentPage === id) ? 'active' : '';
    html += `<div class="nav-item ${active}" data-page="${id}">
      <span class="dot ${b.severity}"></span>${b.name}
    </div>`;
  });
  html += '<div class="nav-group-label">Field Guide</div>';
  html += `<div class="nav-item ${currentPage==='recon'?'active':''}" data-page="recon"><span class="dot low" style="background:var(--text-faint)"></span>Global Recon</div>`;
  html += `<div class="nav-item ${currentPage==='tools'?'active':''}" data-page="tools"><span class="dot low" style="background:var(--text-faint)"></span>Free Toolkit</div>`;
  html += '<div class="nav-group-label">Target Workspace</div>';
  html += `<div class="nav-item ${currentPage==='workspace'?'active':''}" data-page="workspace"><span class="dot low" style="background:var(--accent)"></span>Notes &amp; Files</div>`;
  nav.innerHTML = html;

  nav.querySelectorAll('.nav-item').forEach(el => {
    el.addEventListener('click', () => {
      currentPage = el.dataset.page;
      currentTab = 'recon';
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
  { id: 'tools', label: 'Tools' },
  { id: 'report', label: 'Report' },
];

async function renderBugPage(bug) {
  const main = document.getElementById('main');
  const tabsHtml = TABS.map(t => `<div class="tab ${currentTab===t.id?'active':''}" data-tab="${t.id}">${t.label}</div>`).join('');

  let linkedFilesHtml = '';
  if (currentTargetId) {
    const items = await dbGetByIndex('items', 'targetId', currentTargetId);
    const files = items.filter(i => i.type === 'file' && i.linkedBug === bug.id);
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
    </div>
    <div class="tabs">${tabsHtml}</div>
    <div id="tabContent"></div>
  `;

  renderTabContent(bug, linkedFilesHtml);

  main.querySelectorAll('.tab').forEach(el => {
    el.addEventListener('click', () => {
      currentTab = el.dataset.tab;
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
      `</div>` + (currentTab==='payloads' && linkedFilesHtml ? linkedFilesHtml : '');
    return;
  }
  if (currentTab === 'report') {
    el.innerHTML = `<div class="panel active"><h3>Report Template</h3><div class="report-box">${escapeHtml(bug.report)}</div></div>`;
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
// STATIC PAGES: Global Recon, Tools
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

// ============================================================
// WORKSPACE PAGE
// ============================================================

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

  const bugOptions = BUG_ORDER.map(id => `<option value="${id}">${BUGS[id].name}</option>`).join('') + `<option value="general">General</option>`;

  main.innerHTML = `
    <div class="case-header">
      <div class="case-meta"><span>Target Workspace</span></div>
      <h2>${escapeHtml(target.name)}</h2>
      <p>Notes and file references for this target. Files stay as pointers — actual file contents live on your machine.</p>
    </div>

    <div class="ws-section">
      <h3>Add a note</h3>
      <div class="ws-form">
        <textarea id="noteText" placeholder="What did you find / what are you testing next?"></textarea>
      </div>
      <div class="ws-form">
        <select id="noteBug">${bugOptions}</select>
        <button class="btn" id="addNoteBtn">Save note</button>
      </div>
    </div>

    <div class="ws-section">
      <h3>Notes (${notes.length})</h3>
      ${notes.length ? notes.map(n => `
        <div class="note-item">
          ${escapeHtml(n.text)}
          <div class="meta">
            <span class="tags"><span>${escapeHtml(n.linkedBug || 'general')}</span></span>
            <span data-del="${n.id}" style="cursor:pointer;float:right;color:var(--text-faint)">remove</span>
          </div>
        </div>
      `).join('') : '<div class="empty-state">No notes yet.</div>'}
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
        <select id="fileBug">${bugOptions}</select>
      </div>
      <div class="ws-form">
        <input type="text" id="fileNote" placeholder="Optional note (where this came from / what it shows)">
        <button class="btn" id="addFileBtn">Save file reference</button>
      </div>
    </div>

    <div class="ws-section">
      <h3>File references (${files.length})</h3>
      ${files.length ? files.map(f => `
        <div class="file-item">
          ${escapeHtml(f.filename)}
          <div class="meta">
            <span class="tags"><span>${escapeHtml(f.fileTag)}</span><span>${escapeHtml(f.linkedBug||'general')}</span></span>
            ${f.note ? '— '+escapeHtml(f.note) : ''}
            <span data-del="${f.id}" style="cursor:pointer;float:right;color:var(--text-faint)">remove</span>
          </div>
        </div>
      `).join('') : '<div class="empty-state">No files linked yet.</div>'}
    </div>
  `;

  document.getElementById('addNoteBtn').addEventListener('click', async () => {
    const text = document.getElementById('noteText').value.trim();
    if (!text) return;
    const linkedBug = document.getElementById('noteBug').value;
    await dbAdd('items', { targetId: currentTargetId, type: 'note', text, linkedBug });
    renderWorkspacePage();
  });

  document.getElementById('addFileBtn').addEventListener('click', async () => {
    const filename = document.getElementById('fileName').value.trim();
    if (!filename) return;
    const fileTag = document.getElementById('fileTag').value;
    const linkedBug = document.getElementById('fileBug').value;
    const note = document.getElementById('fileNote').value.trim();
    await dbAdd('items', { targetId: currentTargetId, type: 'file', filename, fileTag, linkedBug, note });
    renderWorkspacePage();
  });

  main.querySelectorAll('[data-del]').forEach(el => {
    el.addEventListener('click', async () => {
      await dbDelete('items', Number(el.dataset.del));
      renderWorkspacePage();
    });
  });
}

// ============================================================
// TARGET SELECTOR
// ============================================================

async function renderTargetSelector() {
  const targets = await dbGetAll('targets');
  const select = document.getElementById('targetSelect');
  select.innerHTML = targets.map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join('');
  if (targets.length && !currentTargetId) {
    currentTargetId = targets[0].id;
  }
  if (currentTargetId) select.value = currentTargetId;

  select.onchange = () => {
    currentTargetId = Number(select.value);
    if (currentPage === 'workspace') render();
  };
}

document.getElementById('newTargetBtn').addEventListener('click', async () => {
  const name = prompt('Target / program name:');
  if (!name || !name.trim()) return;
  const id = await dbAdd('targets', { name: name.trim() });
  currentTargetId = id;
  await renderTargetSelector();
  currentPage = 'workspace';
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
  if (currentPage === 'workspace') return renderWorkspacePage();
  const bug = BUGS[currentPage];
  if (bug) return renderBugPage(bug);
}

(async function init() {
  DB = await openDB();
  await renderTargetSelector();
  render();
})();
