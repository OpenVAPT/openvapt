// Check catalogue grid (AG Grid Community, self-hosted).
// Progressive enhancement: the page already contains a plain HTML table, which
// stays visible if scripts are off. This script stores nothing and sends nothing.
// On screens narrower than 640 px the static table is kept and the 425 KB grid
// is never loaded; otherwise the grid script and its two stylesheets are
// loaded when the catalogue scrolls near the viewport.
(function () {
  var dataEl = document.getElementById('catalogue-data');
  var host = document.getElementById('grid');
  if (!dataEl || !host) return;
  if (!window.matchMedia || !window.matchMedia('(min-width: 640px)').matches) return;
  var vendor = (document.currentScript && document.currentScript.getAttribute('data-vendor')) || 'assets/vendor/';
  var loaded = false;
  function css(name) {
    var l = document.createElement('link');
    l.rel = 'stylesheet';
    l.href = vendor + name;
    document.head.appendChild(l);
  }
  function load() {
    if (loaded) return;
    loaded = true;
    css('ag-grid.min.css');
    css('ag-theme-quartz.min.css');
    if (window.agGrid) { mount(); return; }
    var s = document.createElement('script');
    s.src = vendor + 'ag-grid-community.min.js';
    s.defer = true;
    s.onload = mount;
    document.head.appendChild(s);
  }
  var target = document.getElementById('static-table') || host;
  if (window.IntersectionObserver) {
    var io = new IntersectionObserver(function (entries) {
      if (entries.some(function (e) { return e.isIntersecting; })) { io.disconnect(); load(); }
    }, { rootMargin: '400px 0px' });
    io.observe(target);
  } else {
    load();
  }
  function mount() {
  if (!window.agGrid) return;
  var rows = JSON.parse(dataEl.textContent);
  var domainName = { host: 'Server', network: 'Network', web: 'Web Apps' };
  var sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function link(p) {
    var a = document.createElement('a');
    a.href = p.data.id + '.html';
    a.textContent = p.value;
    return a;
  }
  function tag(p) {
    var s = document.createElement('span');
    s.className = 'tag tag-' + p.value;
    s.textContent = p.value.charAt(0).toUpperCase() + p.value.slice(1);
    return s;
  }

  var api = agGrid.createGrid(host, {
    theme: 'legacy',
    rowData: rows,
    domLayout: 'autoHeight',
    pagination: true,
    paginationPageSize: 20,
    paginationPageSizeSelector: [20, 50, 100],
    rowHeight: 48,
    defaultColDef: { sortable: true, resizable: true, filter: true, floatingFilter: false },
    columnDefs: [
      { field: 'id', headerName: 'ID', width: 140, cellClass: 'font-mono', pinned: 'left' },
      { field: 'title', headerName: 'Check', flex: 2, minWidth: 260, cellRenderer: link },
      { field: 'category', headerName: 'Category', width: 210 },
      { field: 'domain', headerName: 'Domain', width: 120, valueFormatter: function (p) { return domainName[p.value] || p.value; } },
      { field: 'severity', headerName: 'Severity', width: 130, cellRenderer: tag,
        comparator: function (a, b) { return sevRank[a] - sevRank[b]; } },
      { field: 'cwe', headerName: 'CWE', flex: 1, minWidth: 140 },
      { field: 'owasp', headerName: 'OWASP Top 10', flex: 1, minWidth: 140 },
      { field: 'wstg', headerName: 'OWASP WSTG', flex: 1, minWidth: 140 },
      { field: 'effort', headerName: 'Fix Effort', width: 120, valueFormatter: function (p) { return p.value ? p.value.charAt(0).toUpperCase() + p.value.slice(1) : ''; } }
    ]
  });

  var q = document.getElementById('q'), dom = document.getElementById('domain'),
      sev = document.getElementById('severity'), cat = document.getElementById('category'), shown = document.getElementById('shown');
  function apply() {
    api.setGridOption('quickFilterText', q.value);
    api.setFilterModel({
      domain: dom.value ? { filterType: 'text', type: 'equals', filter: dom.value } : null,
      severity: sev.value ? { filterType: 'text', type: 'equals', filter: sev.value } : null,
      category: cat.value ? { filterType: 'text', type: 'equals', filter: cat.value } : null
    });
  }
  api.addEventListener('modelUpdated', function () {
    shown.textContent = api.getDisplayedRowCount() + ' of ' + rows.length + ' checks';
  });
  [q, dom, sev, cat].forEach(function (el) { el.addEventListener('input', apply); });
  document.getElementById('static-table').hidden = true;
  host.hidden = false;
  }
})();
