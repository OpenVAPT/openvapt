// Academy self-check quizzes. Answers are checked in the browser only.
// Nothing is stored, sent or remembered.
(function () {
  Array.prototype.forEach.call(document.querySelectorAll('fieldset.quiz'), function (fs) {
    var answer = fs.getAttribute('data-answer');
    var out = fs.querySelector('.quiz-result');
    fs.addEventListener('change', function (e) {
      if (!e.target || e.target.type !== 'radio') return;
      var ok = e.target.value === answer;
      out.classList.remove('hidden', 'text-green-8', 'text-red-7');
      out.classList.add(ok ? 'text-green-8' : 'text-red-7');
      out.textContent = (ok ? 'Correct. ' : 'Not quite. The answer is: ' + out.getAttribute('data-correct') + '. ') + out.getAttribute('data-explain');
    });
  });
})();
