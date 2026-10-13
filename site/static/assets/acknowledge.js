// Download acknowledgement gate. Every statement must be ticked one by one
// (there is deliberately no 'select all') before the
// download instructions are shown. Nothing is stored, sent or remembered:
// reloading the page asks again, by design.
(function () {
  var form = document.getElementById('ack-form');
  if (!form) return;
  var boxes = Array.prototype.slice.call(form.querySelectorAll('input[type=checkbox]'));
  var btn = document.getElementById('ack-accept');
  var gated = document.getElementById('gated');
  var count = document.getElementById('ack-count');
  gated.hidden = true;
  form.hidden = false;
  function update() {
    var n = boxes.filter(function (b) { return b.checked; }).length;
    btn.disabled = n !== boxes.length;
    count.textContent = n + ' of ' + boxes.length + ' accepted';
  }
  boxes.forEach(function (b) { b.addEventListener('change', update); });
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (btn.disabled) return;
    form.hidden = true;
    gated.hidden = false;
    gated.querySelector('h2').focus();
  });
  update();
})();
