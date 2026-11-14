/* Conn browser runtime: WebCrypto 20-bit muster-pow-v1 solver and live SSE status pills. */
(function () {
  "use strict";

  var POW_LABEL = "muster-pow-v1";
  var POW_DIFFICULTY = 20;
  var POW_BATCH = 256;

  function utcDayString(date) {
    var y = date.getUTCFullYear();
    var m = String(date.getUTCMonth() + 1).padStart(2, "0");
    var d = String(date.getUTCDate()).padStart(2, "0");
    return y + "-" + m + "-" + d;
  }

  function countLeadingZeroBits(bytes) {
    var total = 0;
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i];
      if (b === 0) {
        total += 8;
        continue;
      }
      for (var bit = 7; bit >= 0; bit--) {
        if ((b & (1 << bit)) === 0) {
          total++;
        } else {
          return total;
        }
      }
    }
    return total;
  }

  function buildPrefixBytes(day, a, b, c) {
    var enc = new TextEncoder();
    var parts = [
      enc.encode(POW_LABEL),
      enc.encode(day),
      enc.encode(a),
      enc.encode(b),
      enc.encode(c)
    ];
    var len = 0;
    for (var i = 0; i < parts.length; i++) {
      len += parts[i].length + 1;
    }
    var out = new Uint8Array(len);
    var offset = 0;
    for (var j = 0; j < parts.length; j++) {
      out.set(parts[j], offset);
      offset += parts[j].length;
      out[offset] = 0;
      offset += 1;
    }
    return out;
  }

  async function solveMusterPoW(a, b, c, onProgress) {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("WebCrypto SHA-256 is required to compute proof-of-work in this browser.");
    }
    var day = utcDayString(new Date());
    var prefix = buildPrefixBytes(day, a, b, c);
    var enc = new TextEncoder();
    var counter = 0;

    while (true) {
      var tasks = [];
      var nonces = [];
      for (var i = 0; i < POW_BATCH; i++) {
        var nonce = counter.toString(16);
        counter++;
        nonces.push(nonce);
        var nonceBytes = enc.encode(nonce);
        var msg = new Uint8Array(prefix.length + nonceBytes.length);
        msg.set(prefix, 0);
        msg.set(nonceBytes, prefix.length);
        tasks.push(window.crypto.subtle.digest("SHA-256", msg));
      }
      var digests = await Promise.all(tasks);
      for (var k = 0; k < digests.length; k++) {
        var view = new Uint8Array(digests[k]);
        if (countLeadingZeroBits(view) >= POW_DIFFICULTY) {
          return day + "." + nonces[k];
        }
      }
      if (onProgress && counter % (POW_BATCH * 64) === 0) {
        onProgress(counter);
      }
    }
  }

  function proposalStageLabel(status) {
    switch (status) {
      case "pending_approval":
        return "Proposed";
      case "approved":
        return "Approved";
      case "building":
        return "Building";
      case "live":
        return "Live";
      case "rejected":
        return "Rejected";
      default:
        return status;
    }
  }

  function applyProposalPill(el, id, status) {
    if (!el) {
      return;
    }
    el.setAttribute("data-proposal-id", id);
    el.className = "pill pill-" + status;
    el.textContent = id + ": " + proposalStageLabel(status);
  }

  function updateProposalStatusAcrossDOM(id, status) {
    var nodes = document.querySelectorAll('[data-proposal-id="' + CSS.escape(id) + '"]');
    for (var i = 0; i < nodes.length; i++) {
      applyProposalPill(nodes[i], id, status);
    }
  }

  function bindEditForms() {
    var forms = document.querySelectorAll("[data-edit-form]");
    for (var i = 0; i < forms.length; i++) {
      (function (form) {
        form.addEventListener("submit", async function (ev) {
          ev.preventDefault();
          var btn = form.querySelector('button[type="submit"]');
          var statusEl = form.querySelector("[data-edit-status]");
          var pillEl = form.querySelector("[data-edit-pill]");

          var target = (form.querySelector('[name="target"]').value || "").trim();
          var change = (form.querySelector('[name="change"]').value || "").trim();
          var reason = (form.querySelector('[name="reason"]').value || "").trim();
          var honeypotEl = form.querySelector('[name="honeypot"]');
          var honeypot = honeypotEl ? honeypotEl.value : "";

          if (!target || !change || !reason) {
            statusEl.textContent = "Target, proposed change, and reason are required.";
            return;
          }

          btn.disabled = true;
          statusEl.textContent = "Computing 20-bit SHA-256 proof-of-work...";

          try {
            var pow = await solveMusterPoW(target, change, reason, function (hashes) {
              statusEl.textContent = "Computing proof-of-work (" + hashes.toLocaleString() + " hashes)...";
            });

            statusEl.textContent = "Submitting edit proposal to Muster...";
            var resp = await fetch("/v1/edits", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                target: target,
                change: change,
                reason: reason,
                pow: pow,
                honeypot: honeypot
              })
            });

            if (resp.status === 204) {
              statusEl.textContent = "Submission recorded.";
              btn.disabled = false;
              return;
            }

            var data = await resp.json();
            if (resp.status === 202 && data && data.id) {
              statusEl.textContent = "Accepted for Countersign review.";
              if (pillEl) {
                pillEl.hidden = false;
                applyProposalPill(pillEl, data.id, data.status || "pending_approval");
              }
              btn.textContent = proposalStageLabel(data.status || "pending_approval");
              return;
            }

            var errMsg = (data && data.reason) ? (data.error + ": " + data.reason) : "Request refused.";
            statusEl.textContent = errMsg;
            btn.disabled = false;
          } catch (err) {
            statusEl.textContent = err && err.message ? err.message : "Network error submitting proposal.";
            btn.disabled = false;
          }
        });
      })(forms[i]);
    }
  }

  function bindItemForms() {
    var forms = document.querySelectorAll("[data-item-form]");
    for (var i = 0; i < forms.length; i++) {
      (function (form) {
        form.addEventListener("submit", async function (ev) {
          ev.preventDefault();
          var btn = form.querySelector('button[type="submit"]');
          var statusEl = form.querySelector("[data-item-status]");

          var title = (form.querySelector('[name="title"]').value || "").trim();
          var address = (form.querySelector('[name="address"]').value || "").trim();
          var honeypotEl = form.querySelector('[name="honeypot"]');
          var honeypot = honeypotEl ? honeypotEl.value : "";

          if (!title || !address) {
            statusEl.textContent = "Tool title and reference URL are required.";
            return;
          }

          btn.disabled = true;
          statusEl.textContent = "Computing 20-bit SHA-256 proof-of-work...";

          try {
            var pow = await solveMusterPoW("site-form", title, address, function (hashes) {
              statusEl.textContent = "Computing proof-of-work (" + hashes.toLocaleString() + " hashes)...";
            });

            statusEl.textContent = "Submitting candidate tool to Muster...";
            var resp = await fetch("/v1/items", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                source: "site-form",
                title: title,
                address: address,
                pow: pow,
                honeypot: honeypot
              })
            });

            if (resp.status === 204) {
              statusEl.textContent = "Submission recorded.";
              btn.disabled = false;
              return;
            }

            var data = await resp.json();
            if ((resp.status === 201 || resp.status === 200) && data && data.id) {
              var note = data.duplicate ? "Already tracked as " : "Recorded as ";
              statusEl.textContent = note + data.id + " (state: " + data.state + ").";
              btn.disabled = false;
              return;
            }

            var errMsg = (data && data.reason) ? (data.error + ": " + data.reason) : "Submission refused.";
            statusEl.textContent = errMsg;
            btn.disabled = false;
          } catch (err) {
            statusEl.textContent = err && err.message ? err.message : "Network error submitting item.";
            btn.disabled = false;
          }
        });
      })(forms[i]);
    }
  }

  function connectLiveFeed() {
    if (typeof window.EventSource !== "function") {
      return;
    }
    var badge = document.querySelector("[data-feed-indicator]");
    var lastDepthsMs = Date.now();
    var receivedDepths = false;

    var es = new window.EventSource("/v1/feed");

    function setFeedBadge(state, text) {
      if (!badge) {
        return;
      }
      badge.setAttribute("data-feed-state", state);
      badge.textContent = text;
    }

    es.addEventListener("depths", function (ev) {
      try {
        var d = JSON.parse(ev.data);
        lastDepthsMs = Date.now();
        receivedDepths = true;
        setFeedBadge("live", "SSE LIVE");

        var lanes = ["urgent", "normal", "backfill", "needs_subtool"];
        for (var i = 0; i < lanes.length; i++) {
          var key = lanes[i];
          var el = document.querySelector('[data-depth-lane="' + key + '"]');
          if (el && typeof d[key] === "number") {
            el.textContent = String(d[key]);
          }
        }
      } catch (_) {}
    });

    es.addEventListener("health", function (ev) {
      try {
        var h = JSON.parse(ev.data);
        if (!h || !h.component || !h.state) {
          return;
        }
        var card = document.querySelector('[data-component-card="' + CSS.escape(h.component) + '"]');
        if (!card) {
          return;
        }
        var pill = card.querySelector("[data-component-pill]");
        if (pill) {
          pill.className = "pill pill-" + h.state;
          pill.textContent = h.code ? (h.state + " (" + h.code + ")") : h.state;
        }
      } catch (_) {}
    });

    es.addEventListener("edit", function (ev) {
      try {
        var ed = JSON.parse(ev.data);
        if (!ed || !ed.id || !ed.status) {
          return;
        }
        updateProposalStatusAcrossDOM(ed.id, ed.status);
      } catch (_) {}
    });

    es.onerror = function () {
      setFeedBadge("stale", "SSE RECONNECTING");
    };

    window.setInterval(function () {
      if (receivedDepths && Date.now() - lastDepthsMs > 15000) {
        setFeedBadge("stale", "SSE STALE (>15s)");
      }
    }, 2500);
  }

  document.addEventListener("DOMContentLoaded", function () {
    bindEditForms();
    bindItemForms();
    connectLiveFeed();
  });
})();
