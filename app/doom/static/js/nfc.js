/* Web NFC writing.
 *
 * Availability, stated up front because it shapes the whole feature: Web NFC
 * exists only in Chromium on Android. There is no iOS support at all. QR codes
 * are therefore the universal path and NFC is an enhancement - the page works
 * fully without this file, and says so when the API is missing.
 *
 * A secure context is required. Reaching this host by LAN IP over plain HTTP
 * will not do; that is why the stack terminates TLS in front of the app.
 *
 * External file, no inline handlers: the CSP has no 'unsafe-inline', which is
 * what makes script-src 'self' an actual defence rather than a formality.
 */
(function () {
  "use strict";

  var root = document.getElementById("nfc-panel");
  if (!root) { return; }

  var status = document.getElementById("nfc-status");
  var writeBtn = document.getElementById("nfc-write");
  var lockBtn = document.getElementById("nfc-lock");

  var shareUrl = root.getAttribute("data-share-url");
  var registerUrl = root.getAttribute("data-register-url");
  var csrfToken = root.getAttribute("data-csrf");
  var nodeName = root.getAttribute("data-node-name") || "";

  function say(message, kind) {
    status.textContent = message;
    status.className = "nfc-status " + (kind || "");
  }

  if (!("NDEFReader" in window)) {
    say(
      "This browser cannot write NFC tags. Web NFC works only in Chrome on " +
      "Android. Use the QR code instead - it does the same job on any phone.",
      "muted"
    );
    if (writeBtn) { writeBtn.disabled = true; }
    if (lockBtn) { lockBtn.disabled = true; }
    return;
  }

  if (!window.isSecureContext) {
    say("NFC needs a secure connection (HTTPS). Reach this page over https.", "error");
    if (writeBtn) { writeBtn.disabled = true; }
    return;
  }

  /* Record which physical tag was bound to this node. CSRF-protected: a JSON
   * body is not an exemption. */
  function registerTag(uid) {
    if (!uid || !registerUrl) { return Promise.resolve(); }
    return fetch(registerUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken
      },
      credentials: "same-origin",
      body: JSON.stringify({ uid: uid })
    }).catch(function () { /* recording is best-effort; the tag is written */ });
  }

  function write(makeReadOnly) {
    var ndef = new NDEFReader();
    say("Hold the tag against the back of the phone…");

    /* The tag carries a URL and a name - never inventory contents. The label
     * is a permanent pointer to a node, so refilling a tote or moving a shelf
     * never means rewriting a tag. */
    var records = [
      { recordType: "url", data: shareUrl }
    ];
    if (nodeName) {
      records.push({ recordType: "text", data: nodeName });
    }

    ndef.write({ records: records }, { overwrite: true })
      .then(function () {
        if (makeReadOnly) {
          /* Irreversible in hardware. Stops a passer-by repointing the tag at
           * a site of their choosing (T-13) - worth doing on anything left in
           * a space others can reach. */
          return ndef.makeReadOnly().then(function () {
            say("Tag written and permanently locked.", "ok");
          });
        }
        say("Tag written.", "ok");
      })
      .catch(function (error) {
        if (error && error.name === "NotAllowedError") {
          say("Permission denied. Allow NFC access and try again.", "error");
        } else if (error && error.name === "NotSupportedError") {
          say("No NFC hardware available on this device.", "error");
        } else {
          say("Could not write to the tag. Try repositioning it.", "error");
        }
      });
  }

  if (writeBtn) {
    writeBtn.addEventListener("click", function () { write(false); });
  }
  if (lockBtn) {
    lockBtn.addEventListener("click", function () {
      if (window.confirm("Locking a tag is permanent and cannot be undone. Continue?")) {
        write(true);
      }
    });
  }

  /* Read mode: captures the tag's serial so it can be recognised later. */
  var scanBtn = document.getElementById("nfc-scan");
  if (scanBtn) {
    scanBtn.addEventListener("click", function () {
      var reader = new NDEFReader();
      reader.scan()
        .then(function () {
          say("Scanning - hold a tag against the phone…");
          reader.onreading = function (event) {
            say("Read tag " + event.serialNumber, "ok");
            registerTag(event.serialNumber);
          };
        })
        .catch(function () { say("Could not start scanning.", "error"); });
    });
  }
})();
