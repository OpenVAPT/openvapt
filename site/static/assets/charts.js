// Charts (Apache ECharts, self-hosted). Data is embedded in the page as JSON,
// generated from the check registry at build time. Nothing is fetched or stored.
(function () {
  if (!window.echarts) return;
  var dataEl = document.getElementById('chart-data');
  if (!dataEl) return;
  var d = JSON.parse(dataEl.textContent);
  var font = { fontFamily: 'IBM Plex Sans, system-ui, sans-serif', color: 'rgba(0,0,0,.65)' };
  var sevColors = { Critical: '#cf1322', High: '#d4380d', Medium: '#d48806', Low: '#2f54eb', Info: '#8c8c8c' };
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var charts = [];

  function mount(id, option) {
    var el = document.getElementById(id);
    if (!el) return;
    var c = echarts.init(el, null, { renderer: 'svg' });
    option.animation = !reduce;
    option.textStyle = font;
    c.setOption(option);
    charts.push(c);
  }

  mount('chart-severity', {
    grid: { left: 8, right: 24, top: 16, bottom: 8, containLabel: true },
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    xAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#f0f0f0' } } },
    yAxis: { type: 'category', inverse: true, data: d.severity.map(function (s) { return s.name; }), axisTick: { show: false } },
    series: [{ type: 'bar', barWidth: 18, name: 'Checks', data: d.severity.map(function (s) {
      return { value: s.value, itemStyle: { color: sevColors[s.name], borderRadius: [0, 4, 4, 0] } };
    }), label: { show: true, position: 'right' } }]
  });

  mount('chart-domain', {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0, icon: 'circle' },
    color: ['#1677ff', '#13c2c2', '#722ed1'],
    series: [{ type: 'pie', radius: ['48%', '72%'], center: ['50%', '44%'], name: 'Checks',
      label: { formatter: '{b}\n{c}' }, itemStyle: { borderColor: '#fff', borderWidth: 2 }, data: d.domain }]
  });

  mount('chart-owasp', {
    grid: { left: 8, right: 24, top: 16, bottom: 8, containLabel: true },
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    xAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#f0f0f0' } } },
    yAxis: { type: 'category', inverse: true, data: d.owasp.map(function (s) { return s.name; }), axisTick: { show: false } },
    series: [{ type: 'bar', barWidth: 16, name: 'Checks', itemStyle: { color: '#1677ff', borderRadius: [0, 4, 4, 0] },
      data: d.owasp.map(function (s) { return s.value; }), label: { show: true, position: 'right' } }]
  });

  var sevOrder = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  if (d.matrix && d.categories) {
    mount('chart-catsev', {
      grid: { left: 8, right: 24, top: 40, bottom: 8, containLabel: true },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      legend: { top: 0, icon: 'roundRect' },
      xAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#f0f0f0' } } },
      yAxis: { type: 'category', inverse: true, data: d.categories, axisTick: { show: false } },
      series: sevOrder.map(function (sv, i) {
        return { name: sv, type: 'bar', stack: 'total', barWidth: 18, itemStyle: { color: sevColors[sv] },
          emphasis: { focus: 'series' }, data: d.matrix.map(function (row) { return row[i]; }) };
      })
    });
    var cells = [], max = 1;
    d.matrix.forEach(function (row, y) { row.forEach(function (v, x) { cells.push([x, y, v]); if (v > max) max = v; }); });
    mount('chart-heat', {
      grid: { left: 8, right: 16, top: 8, bottom: 60, containLabel: true },
      tooltip: { formatter: function (p) { return d.categories[p.value[1]] + '<br>' + sevOrder[p.value[0]] + ': ' + p.value[2]; } },
      xAxis: { type: 'category', data: sevOrder, splitArea: { show: true } },
      yAxis: { type: 'category', data: d.categories, inverse: true, splitArea: { show: true } },
      visualMap: { min: 0, max: max, calculable: false, orient: 'horizontal', left: 'center', bottom: 0, inRange: { color: ['#f0f5ff', '#1677ff', '#0958d9'] } },
      series: [{ type: 'heatmap', data: cells, label: { show: true }, itemStyle: { borderColor: '#fff', borderWidth: 2 } }]
    });
  }
  function hbar(id, items, color) {
    if (!items) return;
    mount(id, {
      grid: { left: 8, right: 32, top: 8, bottom: 8, containLabel: true },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      xAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#f0f0f0' } } },
      yAxis: { type: 'category', inverse: true, data: items.map(function (s) { return s.name; }), axisTick: { show: false }, axisLabel: { width: 220, overflow: 'truncate' } },
      series: [{ type: 'bar', barWidth: 14, itemStyle: { color: color, borderRadius: [0, 4, 4, 0] }, data: items.map(function (s) { return s.value; }), label: { show: true, position: 'right' } }]
    });
  }
  hbar('chart-cis', d.cis, '#1677ff');
  hbar('chart-csf', d.csf, '#13c2c2');

  if (window.ResizeObserver) {
    var ro = new ResizeObserver(function () { charts.forEach(function (c) { c.resize(); }); });
    charts.forEach(function (c) { ro.observe(c.getDom()); });
  }
})();
