// Citation helpers: the header Cite panel, copy buttons, the style switcher
// and today's access date.
// Runs only in the browser. Nothing is stored, sent or remembered.
(function () {
  // Show today's date as the access date, in each style's own format.
  var M = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  var S = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var d = new Date(), y = d.getFullYear(), m = d.getMonth(), day = d.getDate();
  var fmt = {
    long: day + ' ' + M[m] + ' ' + y,
    us: M[m] + ' ' + day + ', ' + y,
    iso: y + '-' + String(m + 1).padStart(2, '0') + '-' + String(day).padStart(2, '0'),
    van: y + ' ' + S[m] + ' ' + day,
    ieee: day + ' ' + S[m] + (S[m] === 'May' ? ' ' : '. ') + y
  };
  Array.prototype.forEach.call(document.querySelectorAll('[data-date]'), function (el) {
    var v = fmt[el.getAttribute('data-date')];
    if (v) el.textContent = v;
  });

  // Copy buttons.
  function announce(btn, msg) {
    var scope = btn.closest('[data-copy-scope]') || document;
    var live = scope.querySelector('[data-copy-status]');
    if (live) { live.textContent = ''; setTimeout(function () { live.textContent = msg; }, 30); }
  }
  function done(btn, label) {
    var span = btn.querySelector('span');
    if (!btn._label) btn._label = span.textContent;
    btn.setAttribute('data-copied', '');
    span.textContent = 'Copied';
    announce(btn, label + ' copied to the clipboard.');
    clearTimeout(btn._t);
    btn._t = setTimeout(function () { span.textContent = btn._label; btn.removeAttribute('data-copied'); }, 2000);
  }
  function selectText(el) {
    var r = document.createRange();
    r.selectNodeContents(el);
    var s = window.getSelection();
    s.removeAllRanges();
    s.addRange(r);
  }
  function fallback(btn, el, label) {
    selectText(el);
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    if (ok) { done(btn, label); return; }
    el.focus();
    announce(btn, 'Text selected. Press Ctrl+C, or Command+C on a Mac, to copy it.');
  }
  document.addEventListener('click', function (e) {
    var btn = e.target.closest && e.target.closest('[data-copy]');
    if (!btn) return;
    var el = document.getElementById(btn.getAttribute('data-copy'));
    if (!el) return;
    var text = el.textContent;
    var label = (document.getElementById(el.id + '-l') || {}).textContent || 'Citation';
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { done(btn, label); }, function () { fallback(btn, el, label); });
    } else {
      fallback(btn, el, label);
    }
  });

  // Header Cite control: without scripts it is a link to the cite page; with
  // scripts it is a disclosure button that opens a panel in the page flow.
  var toggle = document.querySelector('[data-cite-toggle]');
  var link = document.querySelector('[data-cite-link]');
  var panel = toggle && document.getElementById(toggle.getAttribute('aria-controls'));
  if (toggle && link && panel) {
    toggle.hidden = false;
    link.hidden = true;
    var setOpen = function (open) {
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      panel.hidden = !open;
    };
    toggle.addEventListener('click', function () { setOpen(panel.hidden); });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !panel.hidden) {
        setOpen(false);
        toggle.focus();
      }
    });
  }

  // Style switcher: WAI-ARIA tabs with arrow keys, Home and End.
  Array.prototype.forEach.call(document.querySelectorAll('[data-tabs]'), function (list) {
    var tabs = Array.prototype.slice.call(list.querySelectorAll('[role=tab]'));
    function select(tab, focus) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute('aria-selected', on ? 'true' : 'false');
        t.tabIndex = on ? 0 : -1;
        var p = document.getElementById(t.getAttribute('aria-controls'));
        if (p) p.hidden = !on;
      });
      if (focus) tab.focus();
    }
    list.hidden = false;
    select(tabs.filter(function (t) { return t.getAttribute('aria-selected') === 'true'; })[0] || tabs[0], false);
    list.addEventListener('click', function (e) {
      var t = e.target.closest('[role=tab]');
      if (t) select(t, false);
    });
    list.addEventListener('keydown', function (e) {
      var i = tabs.indexOf(document.activeElement);
      if (i < 0) return;
      var n = { ArrowRight: i + 1, ArrowDown: i + 1, ArrowLeft: i - 1, ArrowUp: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
      if (n === undefined) return;
      e.preventDefault();
      select(tabs[(n + tabs.length) % tabs.length], true);
    });
  });
})();
