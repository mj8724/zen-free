// Keeps a failure that is not this page's from being reported as this page's.
//
// magpie's bridge forwards every error event that reaches the frame to the
// window, and the window then replaces the page with "this page stopped
// working". Code injected into the frame breaks that: MetaMask injects into
// every frame, its inpage script fails in a sandboxed one, and a page that is
// working disappears behind MetaMask's message.
//
// The bridge has two paths, and both are handled here:
//
//   error               a message, a source, and sometimes the Error object
//   unhandledrejection  only the rejection's reason
//
// For an error, the source decides, and the sandbox is why. magpie serves a
// page in a frame sandboxed to scripts alone, so the frame's origin is opaque
// and every file magpie serves it is cross-origin: the browser sanitizes those
// errors to "Script error." and strips the source. Injected code runs as the
// frame's own origin, so its message survives. An unattributable error that
// kept its message therefore came from injected code.
//
// For a rejection there is no source, so the reason's stack decides — and here
// too the sandbox settles the rest. Measured in this frame: a rejection raised
// by the page's own code does not raise the event at all, whether it is
// Promise.reject(Error), Promise.reject(string), an executor or an async throw,
// while an injected script's rejection does, with its reason intact.
//
// This file is loaded before the bridge on purpose: an error event is
// dispatched at the window itself, so listeners there run in the order they
// were registered, and registering first is the only way to stop one being
// forwarded.
//
// Nothing here hides a fault in this page. This page's own errors are
// sanitized and still forwarded, an error whose source names one of this
// page's scripts is forwarded, and a rejection whose stack names one is
// forwarded too. Only what proves it did not come from a file this page
// declared is dropped, and it still reaches the console as before.
(() => {
  function declared() {
    const sources = new Set([location.href]);
    for (const script of document.scripts) if (script.src) sources.add(script.src);
    return sources;
  }

  function namesDeclaredScript(source) {
    if (!source) return false;
    const sources = declared();
    if (sources.has(source)) return true;
    try {
      return sources.has(new URL(source, location.href).href);
    } catch {
      // Not a URL at all, so it cannot name a script this page declared.
      return false;
    }
  }

  function ours(event) {
    const source = event.filename || event.error?.fileName || "";
    if (source) return namesDeclaredScript(source);
    // Unattributable. A file's error arrives sanitized, with no message left
    // to keep; a message that survived means injected code, because that is
    // the only thing running as this frame's own origin.
    return !event.message || event.message === "Script error.";
  }

  function oursRejection(event) {
    const reason = event.reason;
    const stack = reason instanceof Error ? String(reason.stack || "") : "";
    if (!stack) return false;
    for (const source of declared()) if (stack.includes(source)) return true;
    return false;
  }

  addEventListener(
    "error",
    (event) => {
      if (!ours(event)) event.stopImmediatePropagation();
    },
    true,
  );

  addEventListener(
    "unhandledrejection",
    (event) => {
      if (!oursRejection(event)) event.stopImmediatePropagation();
    },
    true,
  );
})();
