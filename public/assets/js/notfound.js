/** 404 page: echoes the requested path into the trace console. */
(function () {
  'use strict';

  var slot = document.getElementById('req-path');
  if (!slot) return;

  // textContent, never innerHTML — the path is attacker-controlled input.
  var path = location.pathname + location.search;
  slot.textContent = path.length > 80 ? path.slice(0, 78) + '…' : path;
})();
