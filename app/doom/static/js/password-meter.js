/* Password strength meter and reveal toggle.
 *
 * ASVS 4.0.3 V2.1.8 asks for a strength meter to help a user choose a stronger
 * password; V2.1.12 asks that the user be able to temporarily view what they
 * typed.  Both are Level 1, and both are advisory: the server is the only
 * authority on whether a password is acceptable.  security/passwords.py
 * enforces length, the breach corpus and the username check regardless of
 * anything decided here, so a user with JavaScript disabled loses the hint and
 * nothing else.
 *
 * Deliberately dependency-free.  Loading zxcvbn would mean either a CDN - which
 * the Content-Security-Policy forbids, and rightly - or vendoring ~800 KB of
 * dictionaries to score a field.  The estimate below is coarser but it is
 * honest about being a hint, and it costs nothing.
 *
 * No inline script and no inline style: script-src is 'self' with no
 * unsafe-inline (security/headers.py), and that is not worth weakening for a
 * progress bar.
 */
(function () {
  "use strict";

  var MIN_LENGTH = 12;

  /* Substrings that make a password predictable regardless of its length.
   * A deliberately short list: the real breach-corpus screen is server-side
   * and covers 10,000 policy-length entries.  This only exists to explain a
   * weak score to the user while they are still typing. */
  var WEAK_FRAGMENTS = [
    "password", "qwerty", "asdf", "zxcv", "letmein", "welcome", "admin",
    "iloveyou", "monkey", "dragon", "sunshine", "princess", "football",
    "doom", "inventory", "warehouse", "storage", "changeme", "secret",
  ];

  var BANDS = [
    { label: "Too short", hint: "Needs at least " + MIN_LENGTH + " characters." },
    { label: "Weak", hint: "Predictable. A few unrelated words would be far stronger." },
    { label: "Fair", hint: "Acceptable, but more length would help more than more symbols." },
    { label: "Good", hint: "Solid." },
    { label: "Strong", hint: "Strong." },
  ];

  function classes(value) {
    var seen = 0;
    if (/[a-z]/.test(value)) seen++;
    if (/[A-Z]/.test(value)) seen++;
    if (/[0-9]/.test(value)) seen++;
    if (/[^A-Za-z0-9]/.test(value)) seen++;
    return seen;
  }

  /* Penalise the two shapes that make a long password weak anyway: one
   * character repeated, and a short unit repeated to reach the length. */
  function isRepetitive(lower) {
    if (/^(.)\1*$/.test(lower)) return true;
    for (var unit = 1; unit <= 4; unit++) {
      var head = lower.slice(0, unit);
      if (head && lower === head.repeat(Math.ceil(lower.length / unit)).slice(0, lower.length)) {
        return true;
      }
    }
    return false;
  }

  function hasRun(lower) {
    var runs = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl"];
    for (var i = 0; i < runs.length; i++) {
      for (var j = 0; j + 4 <= runs[i].length; j++) {
        var slice = runs[i].slice(j, j + 4);
        if (lower.indexOf(slice) !== -1) return true;
        if (lower.indexOf(slice.split("").reverse().join("")) !== -1) return true;
      }
    }
    return false;
  }

  /* 0-4.  Length dominates, which is the whole point of the policy. */
  function score(value) {
    if (value.length < MIN_LENGTH) return 0;

    var lower = value.toLowerCase();
    for (var i = 0; i < WEAK_FRAGMENTS.length; i++) {
      if (lower.indexOf(WEAK_FRAGMENTS[i]) !== -1) return 1;
    }
    if (isRepetitive(lower)) return 1;

    var points = 1;
    if (value.length >= 16) points++;
    if (value.length >= 20) points++;
    if (value.length >= 28) points++;
    if (classes(value) >= 3) points++;
    if (/\s/.test(value.trim())) points++;   // a passphrase, not a string
    if (hasRun(lower)) points--;

    return Math.max(1, Math.min(4, points));
  }

  function buildMeter(input) {
    var wrap = document.createElement("div");
    wrap.className = "pw-meter";

    var bar = document.createElement("div");
    bar.className = "pw-meter-track";
    var fill = document.createElement("div");
    fill.className = "pw-meter-fill";
    bar.appendChild(fill);

    var text = document.createElement("p");
    text.className = "pw-meter-text muted small";
    /* The score is advisory, so announce it politely rather than interrupting
     * a screen reader on every keystroke. */
    text.setAttribute("role", "status");
    text.setAttribute("aria-live", "polite");

    wrap.appendChild(bar);
    wrap.appendChild(text);

    function update() {
      var value = input.value || "";
      if (!value) {
        fill.className = "pw-meter-fill";
        text.textContent = "";
        return;
      }
      var band = score(value);
      /* Width comes from the band class in doom.css rather than an inline
       * style, so nothing here depends on style-src allowing unsafe-inline. */
      fill.className = "pw-meter-fill pw-meter-fill-" + band;
      text.textContent = BANDS[band].label + " - " + BANDS[band].hint;
    }

    input.addEventListener("input", update);
    update();
    return wrap;
  }

  function buildReveal(input) {
    var button = document.createElement("button");
    button.type = "button";           // never submits the form
    button.className = "pw-reveal";
    button.textContent = "Show";
    button.setAttribute("aria-label", "Show password");
    button.setAttribute("aria-pressed", "false");

    button.addEventListener("click", function () {
      var hidden = input.type === "password";
      input.type = hidden ? "text" : "password";
      button.textContent = hidden ? "Hide" : "Show";
      button.setAttribute("aria-label", (hidden ? "Hide" : "Show") + " password");
      button.setAttribute("aria-pressed", hidden ? "true" : "false");
      input.focus();
    });

    return button;
  }

  document.addEventListener("DOMContentLoaded", function () {
    /* Opt in per field via data-password-meter, so the current-password box on
     * the change form is left alone - scoring a password the user already has
     * is noise, and there is nothing they can do about it here. */
    var inputs = document.querySelectorAll("input[type=password][data-password-meter]");

    Array.prototype.forEach.call(inputs, function (input) {
      var field = input.parentNode;
      if (!field) return;
      field.classList.add("pw-field");
      input.insertAdjacentElement("afterend", buildReveal(input));
      field.appendChild(buildMeter(input));
    });
  });
})();
