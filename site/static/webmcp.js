/*
 * WebMCP tools for this website (https://webmachinelearning.github.io/webmcp/).
 * Lets an AI agent running in the visitor's browser read this public marketing
 * site through structured, READ-ONLY tools. Nothing here submits a form, sends
 * data, sets cookies, or calls any host other than this site's own public files
 * (sitemap.xml, llms.txt). Does nothing in browsers without document.modelContext
 * (or the older navigator.modelContext).
 * Self-contained, no dependencies, ES2015 syntax (no optional chaining).
 */
(function () {
  'use strict';
  if (typeof window === 'undefined' || window.__webmcpSiteLoaded) return;
  window.__webmcpSiteLoaded = true;

  var MAX_TEXT = 6000;
  var ORIGIN = location.origin;

  function clip(s, n) {
    s = String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
    n = n || MAX_TEXT;
    return s.length > n ? s.slice(0, n) + ' ...' : s;
  }
  function ok(data) {
    return { content: [{ type: 'text', text: typeof data === 'string' ? data : JSON.stringify(data, null, 2) }] };
  }
  function fail(msg) {
    return { content: [{ type: 'text', text: 'Error: ' + msg }], isError: true };
  }
  function meta(name) {
    var el = document.querySelector('meta[name="' + name + '"],meta[property="' + name + '"]');
    return el ? clip(el.getAttribute('content'), 600) : '';
  }
  function visible(el) {
    if (!el || !el.getClientRects().length) return false;
    var cs = getComputedStyle(el);
    return cs.visibility !== 'hidden' && cs.display !== 'none';
  }
  // Same-origin only; rejects javascript:, data:, and other hosts.
  function sameOriginUrl(raw) {
    try {
      var u = new URL(String(raw), location.href);
      if (u.origin !== ORIGIN || (u.protocol !== 'https:' && u.protocol !== 'http:')) return null;
      return u;
    } catch (e) { return null; }
  }
  function fetchText(path, limit) {
    var u = sameOriginUrl(path);
    if (!u) return Promise.reject(new Error('not same-origin'));
    return fetch(u.href, { credentials: 'omit', redirect: 'follow', cache: 'no-cache' }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      if (sameOriginUrl(r.url) === null) throw new Error('redirected off-site');
      return r.text();
    }).then(function (t) { return limit ? t.slice(0, limit) : t; });
  }

  function jsonLd() {
    var out = [];
    var nodes = document.querySelectorAll('script[type="application/ld+json"]');
    for (var i = 0; i < nodes.length; i++) {
      try {
        var d = JSON.parse(nodes[i].textContent);
        var list = Array.isArray(d) ? d : (d && d['@graph'] ? d['@graph'] : [d]);
        for (var j = 0; j < list.length; j++) if (list[j]) out.push(list[j]);
      } catch (e) { /* skip malformed block */ }
    }
    return out;
  }
  function boundedJsonLd(maxChars) {
    var all = jsonLd(), out = [], used = 0;
    for (var i = 0; i < all.length && out.length < 12; i++) {
      var n = JSON.stringify(all[i]).length;
      if (used + n > maxChars) continue;
      out.push(all[i]); used += n;
    }
    return out;
  }
  // Visible text without icon-font ligatures (e.g. "expand_more") or aria-hidden decoration.
  function cleanText(el) {
    var c = el.cloneNode(true);
    var junk = c.querySelectorAll('[aria-hidden="true"],.material-icons,.material-icons-outlined,.material-symbols-outlined,.material-symbols-rounded,[class*="icon"],svg,script,style');
    for (var i = 0; i < junk.length; i++) junk[i].parentNode.removeChild(junk[i]);
    return clip(c.textContent, 4000);
  }
  // Q&A for answer engines: FAQPage JSON-LD first, then <details><summary> pairs.
  function faqs() {
    var out = [], seen = {};
    jsonLd().forEach(function (n) {
      var t = [].concat(n['@type'] || []);
      if (t.indexOf('FAQPage') === -1) return;
      [].concat(n.mainEntity || []).forEach(function (q) {
        var a = q && q.acceptedAnswer ? [].concat(q.acceptedAnswer)[0] : null;
        if (!q || !q.name || !a) return;
        var k = clip(q.name, 300).toLowerCase();
        if (seen[k]) return; seen[k] = 1;
        out.push({ question: clip(q.name, 300), answer: clip(String(a.text || '').replace(/<[^>]*>/g, ' '), 1500) });
      });
    });
    var ds = document.querySelectorAll('details');
    for (var i = 0; i < ds.length && out.length < 80; i++) {
      var sm = ds[i].querySelector('summary');
      if (!sm || ds[i].closest('nav,header,footer,[role="navigation"],[role="menu"]')) continue;
      var inFaq = !!ds[i].closest('[id*="faq"],[id*="Faq"],[id*="FAQ"],[class*="faq"],[class*="Faq"],[class*="FAQ"],[itemtype*="FAQPage"]');
      if (!inFaq && !/\?\s*$/.test(cleanText(sm))) continue;
      var q = clip(cleanText(sm), 300), k = q.toLowerCase();
      if (!q || seen[k]) continue; seen[k] = 1;
      var body = ds[i].cloneNode(true), bs = body.querySelector('summary');
      if (bs) bs.parentNode.removeChild(bs);
      out.push({ question: q, answer: clip(cleanText(body), 1500) });
    }
    return out;
  }
  function headings() {
    var hs = document.querySelectorAll('main h1,main h2,main h3,h1,h2,h3');
    var seen = new Set(), out = [];
    for (var i = 0; i < hs.length; i++) {
      var h = hs[i];
      if (seen.has(h) || !visible(h)) continue;
      seen.add(h);
      var sec = h.closest('section[id],article[id],div[id]');
      out.push({ level: Number(h.tagName.charAt(1)), text: clip(h.textContent, 160), id: h.id || (sec ? sec.id : '') });
    }
    return out;
  }
  function findSection(q) {
    q = String(q || '').trim();
    if (!q) return null;
    var byId = null;
    try { byId = document.getElementById(q.replace(/^#/, '')); } catch (e) {}
    if (byId) return byId;
    var lq = q.toLowerCase();
    var hs = document.querySelectorAll('h1,h2,h3,h4');
    for (var i = 0; i < hs.length; i++) {
      if (visible(hs[i]) && hs[i].textContent.toLowerCase().indexOf(lq) !== -1) return hs[i];
    }
    return null;
  }
  function sectionText(el) {
    var box = el.closest('section,article') || el.parentElement || el;
    return clip(box.innerText || box.textContent);
  }
  function dialogTriggers() {
    var sel = 'dialog[id],[role="dialog"][id],.modal[id]';
    var dialogs = document.querySelectorAll(sel), out = [];
    for (var i = 0; i < dialogs.length; i++) {
      var d = dialogs[i], id = d.id;
      var label = d.getAttribute('aria-label') || '';
      if (!label) {
        var t = d.querySelector('h1,h2,h3,[class*="title"]');
        label = t ? t.textContent : id;
      }
      var esc = (window.CSS && CSS.escape) ? CSS.escape(id) : id.replace(/[^\w-]/g, '');
      var trig = document.querySelector('[aria-controls="' + esc + '"],[data-target="#' + esc + '"],[data-bs-target="#' + esc + '"],[data-modal="' + esc + '"],[data-open="' + esc + '"],[data-modal-target="' + esc + '"],[data-dialog="' + esc + '"],a[href="#' + esc + '"]');
      out.push({ id: id, el: d, title: clip(label, 120), trigger: trig });
    }
    return out;
  }

  var tools = [
    {
      name: 'get_site_overview',
      description: 'Get a factual overview of this website and the organisation, products and services it describes: page title, description, structured data (JSON-LD) and the start of the site\'s llms.txt summary. Use this first to understand what the site offers.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true },
      execute: function () {
        var data = {
          site: ORIGIN,
          page_url: location.href.split('#')[0],
          title: clip(document.title, 200),
          description: meta('description') || meta('og:description'),
          site_name: meta('og:site_name'),
          language: document.documentElement.lang || '',
          canonical: (document.querySelector('link[rel="canonical"]') || {}).href || '',
          other_languages: Array.prototype.map.call(document.querySelectorAll('link[rel="alternate"][hreflang]'), function (l) { return { lang: l.getAttribute('hreflang'), url: l.href }; }).slice(0, 20),
          structured_data: boundedJsonLd(12000)
        };
        return fetchText('/llms.txt', 8000).then(function (t) {
          data.llms_txt_excerpt = t; return ok(data);
        }, function () { return ok(data); });
      }
    },
    {
      name: 'list_site_pages',
      description: 'List the public pages of this website from its sitemap.xml, optionally filtered by a keyword in the URL. Returns page URLs and last-modified dates.',
      inputSchema: {
        type: 'object',
        properties: {
          keyword: { type: 'string', description: 'Optional word to filter page URLs, e.g. "pricing" or "faq".' },
          limit: { type: 'integer', minimum: 1, maximum: 500, description: 'Maximum number of pages to return (default 200).' }
        },
        additionalProperties: false
      },
      annotations: { readOnlyHint: true },
      execute: function (args) {
        args = args || {};
        var kw = String(args.keyword || '').toLowerCase();
        var limit = Math.min(Math.max(parseInt(args.limit, 10) || 200, 1), 500);
        function parse(xml) {
          var doc = new DOMParser().parseFromString(xml, 'application/xml');
          return { urls: doc.getElementsByTagName('url'), maps: doc.getElementsByTagName('sitemap'), doc: doc };
        }
        function locOf(n) { var l = n.getElementsByTagName('loc')[0]; return l ? l.textContent.trim() : ''; }
        function lmOf(n) { var l = n.getElementsByTagName('lastmod')[0]; return l ? l.textContent.trim() : ''; }
        return fetchText('/sitemap.xml', 2000000).then(function (xml) {
          var p = parse(xml);
          if (p.urls.length || !p.maps.length) return [p];
          var subs = [];
          for (var i = 0; i < p.maps.length && i < 10; i++) {
            var u = sameOriginUrl(locOf(p.maps[i]));
            if (u) subs.push(fetchText(u.pathname, 2000000).then(parse, function () { return null; }));
          }
          return Promise.all(subs);
        }).then(function (parts) {
          var pages = [];
          parts.forEach(function (p) {
            if (!p) return;
            for (var i = 0; i < p.urls.length; i++) {
              var loc = locOf(p.urls[i]);
              if (!loc || (kw && loc.toLowerCase().indexOf(kw) === -1)) continue;
              pages.push({ url: loc, lastmod: lmOf(p.urls[i]) });
            }
          });
          return ok({ total: pages.length, pages: pages.slice(0, limit) });
        }, function (e) { return fail('could not read sitemap.xml (' + e.message + ')'); });
      }
    },
    {
      name: 'get_faq',
      description: 'Get the frequently asked questions and their answers published on the current page (from its FAQ structured data and expandable FAQ items). Use this to answer common questions about the products or services in the site\'s own words.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true },
      execute: function () {
        var list = faqs();
        return list.length ? ok({ page_url: location.href.split('#')[0], faqs: list }) : ok('This page has no FAQ. Use list_site_pages with keyword "faq" to find the FAQ page.');
      }
    },
    {
      name: 'get_page_sections',
      description: 'Get the outline of the page currently open: its headings in order, with section ids that can be passed to read_page_section or go_to_section.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true },
      execute: function () {
        return ok({ page_url: location.href.split('#')[0], title: clip(document.title, 200), sections: headings().slice(0, 150) });
      }
    },
    {
      name: 'read_page_section',
      description: 'Read the text of one section of the current page, found by section id or by words from its heading.',
      inputSchema: {
        type: 'object',
        properties: { section: { type: 'string', description: 'Section id (from get_page_sections) or words from the heading.' } },
        required: ['section'],
        additionalProperties: false
      },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      execute: function (args) {
        var el = findSection(args && args.section);
        if (!el) return fail('no section matches "' + clip(args && args.section, 80) + '"');
        return ok({ section: clip(el.textContent, 160), text: sectionText(el) });
      }
    },
    {
      name: 'search_page',
      description: 'Search the visible text of the current page for a word or phrase and return short matching snippets with their nearest heading.',
      inputSchema: {
        type: 'object',
        properties: { query: { type: 'string', minLength: 2, maxLength: 120, description: 'Word or phrase to find.' } },
        required: ['query'],
        additionalProperties: false
      },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      execute: function (args) {
        var q = String((args && args.query) || '').trim().toLowerCase();
        if (q.length < 2) return fail('query is too short');
        var blocks = document.querySelectorAll('main p,main li,main td,main dd,main summary,p,li,td,dd,summary,h1,h2,h3,h4');
        var hits = [], seen = new Set();
        for (var i = 0; i < blocks.length && hits.length < 25; i++) {
          var b = blocks[i];
          if (seen.has(b)) continue;
          seen.add(b);
          var t = (b.textContent || '').replace(/\s+/g, ' ');
          var k = t.toLowerCase().indexOf(q);
          if (k === -1 || !visible(b)) continue;
          var sec = b.closest('section,article');
          var h = sec ? sec.querySelector('h1,h2,h3') : null;
          hits.push({ snippet: clip(t.slice(Math.max(0, k - 120), k + q.length + 160), 320), heading: h ? clip(h.textContent, 120) : '' });
        }
        return ok({ query: q, matches: hits });
      }
    },
    {
      name: 'go_to_section',
      description: 'Scroll the current page to a section so the visitor can see it, found by section id or words from its heading.',
      inputSchema: {
        type: 'object',
        properties: { section: { type: 'string', description: 'Section id or words from the heading.' } },
        required: ['section'],
        additionalProperties: false
      },
      execute: function (args) {
        var el = findSection(args && args.section);
        if (!el) return fail('no section matches "' + clip(args && args.section, 80) + '"');
        var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
        el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
        return ok('Scrolled to "' + clip(el.textContent, 120) + '".');
      }
    },
    {
      name: 'open_site_page',
      description: 'Open another page of this same website in the current tab. Only addresses on this site are allowed.',
      inputSchema: {
        type: 'object',
        properties: { url: { type: 'string', description: 'A page address or path on this site, e.g. "/faq" or a URL from list_site_pages.' } },
        required: ['url'],
        additionalProperties: false
      },
      execute: function (args) {
        var u = sameOriginUrl(args && args.url);
        if (!u) return fail('only pages on ' + ORIGIN + ' can be opened');
        // Public pages only: never sign the visitor out, reach admin/API endpoints or trigger actions.
        if (/(log-?out|sign-?out|delete|remove|unsubscribe|ai-tools|\/api\/|\/admin|\/tools\/|action=|token=)/i.test(u.pathname + u.search))
          return fail('that address is not a public page');
        setTimeout(function () { location.assign(u.href); }, 50);
        return ok('Opening ' + u.href);
      }
    },
    {
      name: 'get_contact_options',
      description: 'List the ways to contact this business that are published on the current page: contact or demo page links, email, phone and WhatsApp links. Returns them only; it does not send anything.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true },
      execute: function () {
        var links = document.querySelectorAll('a[href]'), out = [], keys = {};
        var rx = /contact|demo|enquir|inquir|quote|book|hubungi|support/i;
        for (var i = 0; i < links.length && out.length < 40; i++) {
          var a = links[i], href = a.getAttribute('href') || '', kind = '';
          if (/^mailto:/i.test(href)) kind = 'email';
          else if (/^tel:/i.test(href)) kind = 'phone';
          else if (/^https:\/\/(wa\.me|api\.whatsapp\.com)\//i.test(href)) kind = 'whatsapp';
          else if (sameOriginUrl(href) && rx.test(href + ' ' + a.textContent)) kind = 'page';
          if (!kind) continue;
          var full = kind === 'page' ? sameOriginUrl(href).href : href.split('?')[0];
          if (keys[full]) continue;
          keys[full] = 1;
          out.push({ type: kind, label: clip(a.textContent || a.getAttribute('aria-label'), 100), href: full });
        }
        return ok({ contacts: out });
      }
    },
    {
      name: 'list_page_dialogs',
      description: 'List the pop-up dialogs (modals) on the current page that can be opened with open_page_dialog.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true },
      execute: function () {
        return ok({ dialogs: dialogTriggers().map(function (d) { return { id: d.id, title: d.title, can_open: !!d.trigger || d.el instanceof HTMLDialogElement }; }) });
      }
    },
    {
      name: 'open_page_dialog',
      description: 'Open one pop-up dialog (modal) on the current page by its id, the same way the visitor would by pressing its button. It only shows the dialog; it never submits a form inside it.',
      inputSchema: {
        type: 'object',
        properties: { id: { type: 'string', description: 'Dialog id from list_page_dialogs.' } },
        required: ['id'],
        additionalProperties: false
      },
      execute: function (args) {
        var id = String((args && args.id) || '');
        var list = dialogTriggers(), d = null;
        for (var i = 0; i < list.length; i++) if (list[i].id === id) d = list[i];
        if (!d) return fail('no dialog with id "' + clip(id, 60) + '"');
        var t = d.trigger;
        if (t && !(t.type === 'submit' || (t.form && t.tagName === 'BUTTON' && t.type !== 'button'))) {
          t.click();
          return ok('Opened "' + d.title + '".');
        }
        var el = document.getElementById(id);
        if (el instanceof HTMLDialogElement && !el.open) { el.showModal(); return ok('Opened "' + d.title + '".'); }
        return fail('this dialog cannot be opened directly');
      }
    }
  ];

  // Declarative WebMCP: describe public enquiry forms so an agent can fill them for
  // the visitor to review. Never sets toolautosubmit, so a person always presses Submit.
  // Skips anything with passwords, payment, file upload or login/admin purpose.
  function annotateForms() {
    var forms = document.querySelectorAll('form');
    var used = {};
    for (var i = 0; i < forms.length; i++) {
      var f = forms[i];
      if (f.hasAttribute('toolname')) continue;
      if (f.querySelector('input[type="password"],input[type="file"],input[autocomplete^="cc-"]')) continue;
      if (/card|cvv|cvc|iban|account.?no/i.test(Array.prototype.map.call(f.elements, function (x) { return x.name || ''; }).join(' '))) continue;
      var sig = ((f.id || '') + ' ' + (f.getAttribute('name') || '') + ' ' + (f.getAttribute('action') || '') + ' ' + (f.className || '')).toLowerCase();
      if (/login|signin|sign-in|admin|auth|register|signup|checkout|pay/.test(sig)) continue;
      var fields = f.querySelectorAll('input[name],textarea[name],select[name]');
      var hasText = false;
      for (var j = 0; j < fields.length; j++) if (fields[j].type !== 'hidden') hasText = true;
      if (!hasText) continue;
      var isSearch = f.getAttribute('role') === 'search' || !!f.querySelector('input[type="search"]') || /search/.test(sig);
      var base = isSearch ? 'search_site' : (/demo/.test(sig) ? 'request_demo' : (/newsletter|subscribe/.test(sig) ? 'subscribe_newsletter' : 'send_enquiry'));
      var name = base, n = 2;
      while (used[name]) name = base + '_' + (n++);
      used[name] = 1;
      var head = f.closest('section,article,dialog,[role="dialog"]');
      var h = head ? head.querySelector('h1,h2,h3') : null;
      var label = h ? clip(h.textContent, 80) : '';
      f.setAttribute('toolname', name);
      f.setAttribute('tooldescription', isSearch
        ? 'Search this website' + (label ? ' (' + label + ')' : '') + '.'
        : 'Fill in the "' + (label || 'enquiry') + '" form on this website for the visitor to review and submit themselves.');
      for (var k = 0; k < fields.length; k++) {
        var fl = fields[k];
        if (fl.type === 'hidden' || fl.hasAttribute('toolparamdescription')) continue;
        var lab = (fl.id && document.querySelector('label[for="' + ((window.CSS && CSS.escape) ? CSS.escape(fl.id) : fl.id) + '"]')) || fl.closest('label');
        var desc = clip((lab ? lab.textContent : '') || fl.getAttribute('aria-label') || fl.getAttribute('placeholder') || fl.name, 120);
        if (desc) fl.setAttribute('toolparamdescription', desc);
      }
    }
  }

  // Current draft: document.modelContext; earlier Chrome previews: navigator.modelContext.
  function register() {
    var mc = (document.modelContext) || (navigator.modelContext);
    if (!mc) return;
    var ready = tools.map(function (t) {
      var run = t.execute;
      var copy = {};
      for (var k in t) if (Object.prototype.hasOwnProperty.call(t, k)) copy[k] = t[k];
      copy.title = t.name.replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
      copy.title = copy.title.replace(/\bFaq\b/, 'FAQ');
      copy.execute = function (input) {
        try { return Promise.resolve(run(input || {})).catch(function (e) { return fail(String(e && e.message || e)); }); }
        catch (e) { return Promise.resolve(fail(String(e && e.message || e))); }
      };
      return copy;
    });
    try {
      if (typeof mc.registerTool === 'function') {
        ready.forEach(function (t) {
          try {
            var p = mc.registerTool(t);
            if (p && typeof p.catch === 'function') p.catch(function () {});
          } catch (e) { /* already registered */ }
        });
      } else if (typeof mc.provideContext === 'function') {
        mc.provideContext({ tools: ready });
      }
    } catch (e) { /* never break the page */ }
  }

  function start() {
    try { annotateForms(); } catch (e) {}
    register();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
