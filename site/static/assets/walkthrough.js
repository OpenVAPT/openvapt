/* openvapt.com walkthrough player. Self-hosted, no dependencies, no storage, no network.
   The scenes are plain HTML in the page (readable without JavaScript). This script only
   reveals them over time: each scene is compiled into a timeline and drawn from a single
   clock, so Pause, Replay and chapter jumps are exact and never leave half-typed text.
   It pauses when the walkthrough is off-screen or the tab is hidden, and with
   prefers-reduced-motion it shows static stills that the chapter buttons switch between. */
(function () {
  'use strict';
  var HOLD = 2600;          // ms a finished scene stays before the next one
  var LINE = 150;           // ms between output lines
  var START = 450;          // ms before the first line of a scene

  function charDelay(ch, i) {
    if (ch === ' ') return 22;
    return 30 + ((i * 7919) % 5) * 9; // steady, human-like cadence without randomness
  }

  function setup(root) {
    var stage = root.querySelector('[data-wt-stage]');
    var scenes = Array.prototype.slice.call(root.querySelectorAll('.wt-scene'));
    var controls = root.querySelector('[data-wt-controls]');
    var playBtn = root.querySelector('[data-wt-play]');
    var replayBtn = root.querySelector('[data-wt-replay]');
    var chBtns = Array.prototype.slice.call(root.querySelectorAll('[data-wt-ch]'));
    var caption = root.querySelector('[data-wt-caption]');
    var live = root.querySelector('[data-wt-live]');
    var loop = root.hasAttribute('data-loop');
    var mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    var reduce = mq.matches;

    // Compile every scene into a timeline of line events.
    var timelines = scenes.map(function (scene) {
      var t = START, items = [];
      var gap = +scene.getAttribute('data-gap') || LINE, hold = +scene.getAttribute('data-hold') || HOLD;
      Array.prototype.forEach.call(scene.querySelectorAll('.ln'), function (el) {
        var tx = el.getAttribute('data-k') === 'cmd' ? el.querySelector('.tx') : null;
        var item = { el: el, start: t, tx: tx, shown: null, typed: -1 };
        if (tx) {
          item.text = tx.textContent;
          item.steps = [];
          var acc = 0;
          for (var i = 0; i < item.text.length; i++) { acc += charDelay(item.text[i], i); item.steps.push(acc); }
          t += 260 + acc + 380; // a short beat before typing and after Enter
          item.end = t - 380;
        } else {
          t += gap;
          item.end = item.start;
        }
        items.push(item);
      });
      return { scene: scene, items: items, length: t + hold, scroller: scene.querySelector('.term, .rp, .viz'),
        pointer: scene.querySelector('.wt-pointer'), target: scene.querySelector('[data-point]') };
    });

    root.classList.add('wt-js');
    controls.hidden = false;

    var cur = 0, time = 0, playing = false, userPaused = false, visible = false, last = 0, raf = 0;

    function draw(idx, tm) {
      var tl = timelines[idx], lastShown = null;
      tl.items.forEach(function (it) {
        var show = tm >= it.start;
        if (show !== it.shown) { it.el.classList.toggle('is-off', !show); it.shown = show; }
        if (it.tx) {
          var n = 0, typing = false;
          if (tm >= it.end) n = it.text.length;
          else if (tm > it.start + 260) {
            var e = tm - it.start - 260;
            while (n < it.steps.length && it.steps[n] <= e) n++;
            typing = true;
          } else if (show) typing = true;
          if (n !== it.typed) { it.tx.textContent = it.text.slice(0, n); it.typed = n; }
          it.el.classList.toggle('is-typing', typing && show);
        }
        if (show) lastShown = it.el;
      });
      if (tl.scroller && lastShown && !reduce) {
        var want = lastShown.offsetTop + lastShown.offsetHeight - tl.scroller.clientHeight + 16;
        if (tl.scroller.classList.contains('rp') && tl.target && tm >= tl.items[tl.items.length - 1].start) want = tl.target.offsetTop - 24;
        if (want > tl.scroller.scrollTop + 1) tl.scroller.scrollTop = want;
      }
      if (tl.pointer && tl.target) tl.pointer.classList.toggle('is-on', tm >= tl.items[tl.items.length - 1].start + 500);
      chBtns.forEach(function (b, i) {
        var f = i < idx ? 1 : i > idx ? 0 : Math.min(1, tm / tl.length);
        b.firstChild.style.transform = 'scaleX(' + f + ')';
      });
    }

    function show(idx, announce) {
      scenes.forEach(function (s, i) {
        s.classList.toggle('is-active', i === idx);
        s.classList.toggle('is-before', i < idx);
        s.setAttribute('aria-hidden', i === idx ? 'false' : 'true');
        if ('inert' in s) s.inert = i !== idx;
      });
      chBtns.forEach(function (b, i) { if (i === idx) b.setAttribute('aria-current', 'step'); else b.removeAttribute('aria-current'); });
      var text = scenes[idx].getAttribute('data-caption') || '';
      caption.textContent = text;
      if (announce) live.textContent = text;
      var sc = timelines[idx].scroller; if (sc) sc.scrollTop = 0;
      timelines[idx].items.forEach(function (it) { it.shown = null; it.typed = -1; });
    }

    function go(idx, announce) {
      cur = idx; time = reduce ? Infinity : 0;
      show(idx, announce);
      draw(cur, time);
    }

    function frame(now) {
      raf = 0;
      if (!playing) return;
      var dt = Math.min(250, now - last); last = now;
      time += dt;
      if (time >= timelines[cur].length) {
        if (cur < scenes.length - 1) { go(cur + 1, false); }
        else if (loop) { go(0, false); }
        else { time = timelines[cur].length; draw(cur, time); setPlaying(false); return; }
      } else draw(cur, time);
      raf = requestAnimationFrame(frame);
    }

    function label() {
      var span = playBtn.querySelector('span');
      span.textContent = playing ? 'Pause' : 'Play';
      root.classList.toggle('is-playing', playing);
    }

    function setPlaying(p) {
      if (reduce) p = false;
      playing = p;
      if (p && !raf) { last = performance.now(); raf = requestAnimationFrame(frame); }
      label();
    }

    function wanted() { return !userPaused && visible && !document.hidden && !reduce; }
    function sync() { setPlaying(wanted() && !(cur === scenes.length - 1 && time >= timelines[cur].length && !loop)); }

    playBtn.addEventListener('click', function () {
      if (playing) { userPaused = true; setPlaying(false); return; }
      userPaused = false;
      if (cur === scenes.length - 1 && time >= timelines[cur].length) go(0, true);
      setPlaying(true);
    });
    replayBtn.addEventListener('click', function () { userPaused = false; go(0, true); sync(); if (!playing && !reduce) setPlaying(true); });
    chBtns.forEach(function (b, i) {
      b.addEventListener('click', function () { go(i, true); if (!reduce && !userPaused) setPlaying(true); });
    });

    if ('IntersectionObserver' in window) {
      new IntersectionObserver(function (es) { visible = es[0].isIntersecting; sync(); }, { threshold: 0.25 }).observe(stage);
    } else { visible = true; }
    document.addEventListener('visibilitychange', sync);

    function applyMotion() {
      reduce = mq.matches;
      root.classList.toggle('wt-still', reduce);
      if (reduce) { setPlaying(false); go(cur, false); } else { go(cur, false); sync(); }
    }
    if (mq.addEventListener) mq.addEventListener('change', applyMotion);
    applyMotion();
  }

  Array.prototype.forEach.call(document.querySelectorAll('[data-wt]'), setup);
})();
