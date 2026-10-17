// Keeps an error that is not this page's from being reported as this page's.
//
// magpie's bridge forwards every error event that reaches the frame to the
// window, and the window then replaces the page with "this page stopped
// working". Code injected into the frame breaks that: MetaMask injects into
// every frame, its inpage script throws "Failed to connect to MetaMask" in a
// sandboxed one, and a page that is working disappears behind that message.
//
// Which errors are this page's can be told apart, and the reason is the
// sandbox rather than a heuristic. magpie serves a page in a frame sandboxed to
// scripts alone, so the frame's origin is opaque and every file magpie serves
// it is cross-origin: the browser sanitizes those errors to "Script error." and
// strips the source. An error that keeps its message therefore did not come
// from a file this page loaded — it came from something injected into the
// frame, which is what a browser extension does.
//
// This file is loaded before the bridge on purpose: an error event is
// dispatched at the window itself, so listeners there run in the order they
// were registered, and registering first is the only way to stop one being
// forwarded.
//
// Nothing here hides a fault in this page. This page's own errors are
// sanitized and still forwarded, and anything that cannot be attributed is
// forwarded too — only an error that proves it did not come from a file this
// page declared is dropped, and it is still reported in the console as before.
(() => {
  function declared() {
    const sources = new Set([location.href]);
    for (const script of document.scripts) if (script.src) sources.add(script.src);
    return sources;
  }

  function ours(event) {
    const source = event.filename || event.error?.fileName || "";
    if (source) {
      // Attributable: it is this page's when it names a script this page
      // declares, the bridge and guard included.
      const sources = declared();
      if (sources.has(source)) return true;
      try {
        return sources.has(new URL(source, location.href).href);
      } catch {
        // Not a URL at all, so it cannot name a script this page declared.
        return false;
      }
    }
    // Unattributable. A file's error arrives sanitized, with no message left to
    // keep; a message that survived means injected code, because that is the
    // only thing that runs as this frame's own origin.
    return !event.message || event.message === "Script error.";
  }

  addEventListener(
    "error",
    (event) => {
      if (!ours(event)) event.stopImmediatePropagation();
    },
    true,
  );
})();
