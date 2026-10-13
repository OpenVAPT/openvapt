// Check catalogue grid (AG Grid Community, self-hosted).
// Progressive enhancement: the page already contains a plain HTML table, which
// stays visible if scripts are off. This script stores nothing and sends nothing.
(function () {
  var dataEl = document.getElementById('catalogue-data');
  var host = document.getElementById('grid');
  if (!dataEl || !host || !window.agGrid) return;
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
      { field: 'domain', headerName: 'Domain', width: 130, valueFormatter: function (p) { return domainName[p.value] || p.value; } },
      { field: 'severity', headerName: 'Severity', width: 130, cellRenderer: tag,
        comparator: function (a, b) { return sevRank[a] - sevRank[b]; } },
      { field: 'cwe', headerName: 'CWE', flex: 1, minWidth: 140 },
      { field: 'owasp', headerName: 'OWASP Top 10', flex: 1, minWidth: 150 }
    ]
  });

  var q = document.getElementById('q'), dom = document.getElementById('domain'),
      sev = document.getElementById('severity'), shown = document.getElementById('shown');
  function apply() {
    api.setGridOption('quickFilterText', q.value);
    api.setFilterModel({
      domain: dom.value ? { filterType: 'text', type: 'equals', filter: dom.value } : null,
      severity: sev.value ? { filterType: 'text', type: 'equals', filter: sev.value } : null
    });
  }
  api.addEventListener('modelUpdated', function () {
    shown.textContent = api.getDisplayedRowCount() + ' of ' + rows.length + ' checks';
  });
  [q, dom, sev].forEach(function (el) { el.addEventListener('input', apply); });
  document.getElementById('static-table').hidden = true;
  host.hidden = false;
})();
