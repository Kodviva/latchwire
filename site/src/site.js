// Only progressive enhancement: the page works without this file.
(function () {
  document.querySelectorAll('.copy').forEach(function (button) {
    var label = button.textContent;
    var timer = null;
    var status = document.getElementById('copy-status');
    button.hidden = false;
    button.addEventListener('click', function () {
      var text = button.parentElement.querySelector('code').textContent;
      var done = function () {
        var copied = button.getAttribute('data-copied');
        button.textContent = copied;
        status.textContent = copied;
        clearTimeout(timer);
        timer = setTimeout(function () {
          button.textContent = label;
          status.textContent = '';
        }, 1800);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, function () {});
      }
    });
  });

  var menu = document.querySelector('.lang');
  document.addEventListener('click', function (event) {
    if (menu.open && !menu.contains(event.target)) menu.open = false;
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && menu.open) {
      menu.open = false;
      menu.querySelector('summary').focus();
    }
  });
})();
