/* Barcode scanning.
 *
 * Uses the browser's native BarcodeDetector where it exists, mirroring how
 * nfc.js handles Web NFC: feature-detected, with the plain text field as the
 * fallback. No vendored library, so script-src 'self' holds unchanged.
 *
 * SECURITY — the important part.
 *
 * A barcode is not a number. Code128 and QR encode arbitrary bytes, anyone can
 * print one, and it arrives wearing the authority of a physical object, which
 * is exactly why it gets trusted when it should not be. `rawValue` is hostile
 * input.
 *
 * Two rules follow, and both are enforced again on the server:
 *
 *   1. Only 8-14 digits are accepted. Anything else is refused outright rather
 *      than sanitised, because a stored hostile value is only a delayed one.
 *   2. A scanned value is NEVER navigated to. Our own QR labels resolve to
 *      share URLs, so a scanner that followed what it read would happily open
 *      an attacker's page from a sticker.
 */
(function () {
  "use strict";

  var panel = document.getElementById("scan-panel");
  if (!panel) { return; }

  var input = panel.querySelector('input[name="barcode"]');
  var button = document.getElementById("scan-start");
  var status = document.getElementById("scan-status");

  /* Same shape as validation.BARCODE_RE. The server re-checks; this only
     avoids a pointless round trip and gives immediate feedback. */
  var GTIN = /^[0-9]{8,14}$/;

  function say(message, kind) {
    status.textContent = message || "";
    status.className = "scan-status muted small " + (kind || "");
  }

  if (!("BarcodeDetector" in window)) {
    button.disabled = true;
    say("This browser cannot scan barcodes — type the digits instead.");
    return;
  }

  var stream = null;

  function stop() {
    if (stream) {
      stream.getTracks().forEach(function (t) { t.stop(); });
      stream = null;
    }
    var video = document.getElementById("scan-video");
    if (video) { video.remove(); }
  }

  button.addEventListener("click", function () {
    if (stream) { stop(); say("Scanning stopped."); return; }

    var detector = new window.BarcodeDetector({
      formats: ["ean_13", "ean_8", "upc_a", "upc_e", "code_128", "itf"]
    });

    navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } })
      .then(function (s) {
        stream = s;
        var video = document.createElement("video");
        video.id = "scan-video";
        video.className = "scan-video";
        video.setAttribute("playsinline", "");
        video.srcObject = s;
        panel.appendChild(video);
        return video.play().then(function () { return video; });
      })
      .then(function (video) {
        say("Point the camera at the barcode…");

        var tick = function () {
          if (!stream) { return; }
          detector.detect(video)
            .then(function (codes) {
              if (!codes.length) { window.setTimeout(tick, 250); return; }

              var raw = String(codes[0].rawValue || "").trim();

              /* The choke point. Anything that is not a GTIN is refused and
                 discarded — never stored, never sent, never followed. */
              if (!GTIN.test(raw)) {
                stop();
                say("That code is not a product barcode, so it was discarded.",
                    "error");
                return;
              }

              stop();
              input.value = raw;
              say("Read " + raw + ".", "ok");

              /* Ask the server what it knows. Note what does NOT happen: the
                 scanned value is never treated as a URL and never navigated
                 to. Our own QR labels resolve to share URLs, so a scanner that
                 followed what it read would open an attacker's page from a
                 sticker. */
              fetch("/items/barcode/" + encodeURIComponent(raw), {
                credentials: "same-origin",
                headers: { "Accept": "application/json" }
              })
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (data) {
                  if (!data) { return; }
                  if (data.source === "local") {
                    say("You already have this: " + data.name, "ok");
                    return;
                  }
                  if (data.source === "remote" && data.name) {
                    var nameField = document.querySelector('input[name="name"]');
                    /* A suggestion, not an assignment: only fill an empty
                       field, and leave it editable. */
                    if (nameField && !nameField.value) {
                      nameField.value = data.name;
                    }
                    say("Suggested from " + data.provider + " — edit if wrong.",
                        "ok");
                  }
                })
                .catch(function () { /* lookup is best effort */ });
            })
            .catch(function () { window.setTimeout(tick, 400); });
        };
        tick();
      })
      .catch(function () {
        say("Could not open the camera — type the digits instead.", "error");
      });
  });

  window.addEventListener("pagehide", stop);
})();
