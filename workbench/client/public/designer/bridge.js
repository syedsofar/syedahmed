// Bridge between the ArchGuard designer and the workbench. The designer keeps its
// model in what it believes is localStorage. Here that storage is replaced by a
// small object: reads return the model the workbench sent, and writes are posted
// to the workbench, which saves them to the project's architecture model.
(function () {
  var seed = null;
  var started = false;
  function post(msg) {
    try { window.parent.postMessage(msg, window.location.origin); } catch (e) { /* not framed */ }
  }
  window.__sawbStore = {
    getItem: function () { return seed; },
    setItem: function (key, value) {
      try { post({ type: 'sawb:designer-save', model: JSON.parse(value) }); } catch (e) { /* ignore malformed */ }
    }
  };
  window.addEventListener('message', function (ev) {
    if (ev.source !== window.parent || ev.origin !== window.location.origin) return;
    var d = ev.data;
    if (!d || d.type !== 'sawb:designer-init') return;
    seed = JSON.stringify(d.model);
    if (!started && typeof window.__archguardStart === 'function') {
      started = true;
      window.__archguardStart();
    }
  });
  post({ type: 'sawb:designer-ready' });
})();
