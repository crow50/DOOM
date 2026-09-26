/* Move a share code from the URL fragment into the request body.
 *
 * A label encodes https://host/t/#<code>.  Everything after the '#' is kept by
 * the browser and never sent to a server, which is the point: the code is a
 * capability, and ASVS 5.0.0-14.2.1 does not allow one to travel in a URL,
 * where it would sit in browser history, leave in Referer and land in every
 * access log on the way.  This reads it, posts it in the form body, and takes
 * it out of the address bar.
 *
 * Progressive enhancement, not a requirement: the form this fills is already
 * on the page and already usable by hand.  Everything below only saves the
 * visitor from typing 43 characters.
 */
(function () {
  "use strict";

  var form = document.getElementById("share-form");
  var status = document.getElementById("share-status");
  var manual = document.getElementById("share-manual");
  if (!form || !manual) {
    return;
  }

  var field = form.querySelector('input[name="token"]');
  if (!field) {
    return;
  }

  /* Must agree with validation.SHARE_TOKEN_PATTERN.  A value failing this is
   * not submitted at all: there is nothing to learn from asking the server
   * about a string this application could not have issued, and not asking
   * keeps a mistyped link out of the rate limit budget. */
  var SHARE_CODE = /^[A-Za-z0-9_-]{43}$/;

  var code = "";
  try {
    /* location.hash keeps the leading '#'.  decodeURIComponent because a
     * scanner or a messaging app may percent-encode it on the way here. */
    code = decodeURIComponent(window.location.hash.replace(/^#/, ""));
  } catch (err) {
    code = "";
  }

  if (!code) {
    return;  /* Nothing in the link: leave the typed-entry form as it is. */
  }

  if (!SHARE_CODE.test(code)) {
    if (status) {
      status.textContent =
        "That link does not carry a usable share code. Enter it by hand.";
    }
    return;
  }

  field.value = code;

  /* Drop the fragment before submitting.  Without this the code stays in the
   * address bar for anyone standing behind the visitor and rides along into a
   * bookmark or a screenshot.  replaceState leaves no history entry, so Back
   * cannot resurrect it either. */
  if (window.history && window.history.replaceState) {
    window.history.replaceState(null, "", window.location.pathname);
  } else {
    window.location.hash = "";
  }

  manual.hidden = true;
  if (status) {
    status.textContent = "Opening…";
  }
  form.submit();
})();
