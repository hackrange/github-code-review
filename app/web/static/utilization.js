/* Utilization: CPU, memory, disk and network, live and over time.
 *
 * The gauges poll the live route.  The trends ask the history route for the
 * range picked, and a trend opened on its own can be dragged across to zoom,
 * with each zoom a new address so the browser's Back button zooms out again.
 * No chart library: the charts are plain SVG, styled from app.css, so they
 * follow dark mode like everything else.
 */
(function () {
  "use strict";

  var root = document.getElementById("utilization");
  if (!root) { return; }

  var SVGNS = "http://www.w3.org/2000/svg";
  var DAY = 86400000;
  var LIVE_URL = root.getAttribute("data-live");
  var HISTORY_URL = root.getAttribute("data-history");
  var PAGE_URL = root.getAttribute("data-page");

  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) { return; }
      if (k === "class") { el.className = v; }
      else if (k.slice(0, 2) === "on") { el.addEventListener(k.slice(2), v); }
      else { el.setAttribute(k, v); }
    });
    (kids || []).forEach(function (kid) {
      if (kid === null || kid === undefined) { return; }
      el.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
    });
    return el;
  }

  // SVG needs createElementNS.  Attributes only.
  function sv(tag, attrs, kids) {
    var el = document.createElementNS(SVGNS, tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (attrs[k] !== null && attrs[k] !== undefined) { el.setAttribute(k, attrs[k]); }
    });
    (kids || []).forEach(function (kid) {
      if (kid === null || kid === undefined) { return; }
      el.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
    });
    return el;
  }

  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }

  function notice(text) {
    return h("div", { class: "util-error", role: "alert" }, [text]);
  }

  function getJson(url) {
    return fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (response) {
        if (response.redirected || response.status === 401 || response.status === 307) {
          window.location.reload();
          throw new Error("Sign in again.");
        }
        return response.json().catch(function () { return {}; }).then(function (data) {
          if (!response.ok) {
            throw new Error(data.detail || "That did not work (" + response.status + ").");
          }
          return data;
        });
      });
  }

  function bytes(n) {
    n = Number(n) || 0;
    if (n < 1024) { return n + " B"; }
    if (n < 1048576) { return (n / 1024).toFixed(1) + " KB"; }
    if (n < 1073741824) { return (n / 1048576).toFixed(1) + " MB"; }
    return (n / 1073741824).toFixed(2) + " GB";
  }

  function rate(n) { return bytes(n || 0) + "/s"; }

  function pct(v) {
    v = Number(v) || 0;
    return (v > 0 && v < 10 ? v.toFixed(1) : String(Math.round(v))) + "%";
  }

  // A 270 degree arc, green, then amber at 75, then red at 90.
  function gauge(caption) {
    var R = 48, C = 2 * Math.PI * R, ARC = C * 0.75;
    var common = { cx: 60, cy: 60, r: R, transform: "rotate(135 60 60)" };
    var track = sv("circle", Object.assign({ class: "gauge-track", "stroke-dasharray": ARC.toFixed(2) + " " + C.toFixed(2) }, common));
    var fill = sv("circle", Object.assign({ class: "gauge-fill", "stroke-dasharray": "0 " + C.toFixed(2) }, common));
    // The caption sits inside the ring under the number.  The gap at the
    // bottom is too tight for text.
    var value = sv("text", { x: 60, y: 62, class: "gauge-value" }, ["-"]);
    var cap = sv("text", { x: 60, y: 80, class: "gauge-caption" }, [caption]);
    var el = sv("svg", { viewBox: "0 0 120 108", class: "gauge", role: "img", "aria-label": caption }, [track, fill, value, cap]);
    el.update = function (p) {
      p = Math.max(0, Math.min(100, Number(p) || 0));
      fill.setAttribute("stroke-dasharray", (ARC * p / 100).toFixed(2) + " " + C.toFixed(2));
      fill.setAttribute("class", "gauge-fill" + (p >= 90 ? " bad" : p >= 75 ? " warn" : ""));
      value.textContent = pct(p);
      el.setAttribute("aria-label", caption + " " + Math.round(p) + " percent");
    };
    return el;
  }

  function niceMax(v) {
    if (!(v > 0)) { return 1; }
    var mag = Math.pow(10, Math.floor(Math.log10(v)));
    var steps = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];
    for (var i = 0; i < steps.length; i += 1) {
      if (steps[i] * mag >= v * 1.05) { return steps[i] * mag; }
    }
    return 10 * mag;
  }

  function timeLabel(t, span) {
    var d = new Date(t);
    if (span <= 2 * DAY) { return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
    if (span <= 62 * DAY) { return d.toLocaleDateString([], { month: "short", day: "numeric" }); }
    return d.toLocaleDateString([], { month: "short", year: "numeric" });
  }

  // series: [{label, cls, key}], points from the server, from and to in ms.
  // opts.open: the card opens in its own tab.  opts.onSelect(from, to): drag
  // across to pick a window.  opts.big: the one chart tab.
  function lineChart(title, points, series, from, to, opts) {
    var W = opts.big ? 1200 : 640, H = opts.big ? 440 : 210, L = 64, RM = 14, T = 14, B = 26;
    var head = h("div", { class: "chart-head" }, [h("h3", null, [title])]);
    var box = h("div", { class: "util-card chart" + (opts.onSelect ? " zoomable" : "") }, [head]);
    if (opts.open) {
      head.appendChild(h("button", {
        type: "button", class: "btn sm chart-open",
        title: "Open " + title + " in a new tab, where you can drag to zoom",
        "aria-label": "Open " + title + " in a new tab"
      }, ["Open in new tab"]));
      box.classList.add("openable");
      // A tap on a phone shows the tooltip.  Only the button opens a tab there.
      var pointer = "mouse";
      box.addEventListener("pointerdown", function (e) { pointer = e.pointerType; });
      box.addEventListener("click", function (e) {
        if (pointer === "touch" && !(e.target.closest && e.target.closest(".chart-open"))) { return; }
        opts.open();
      });
    }
    if (!points.length) {
      box.appendChild(h("div", { class: "empty" }, ["No samples in this range yet."]));
      return box;
    }
    var span = Math.max(1, to - from);
    var top = opts.max || niceMax(Math.max.apply(null, points.map(function (p) {
      return Math.max.apply(null, series.map(function (s) { return Number(p[s.key]) || 0; }));
    })));
    var x = function (t) { return L + (W - L - RM) * (t - from) / span; };
    var y = function (v) { return T + (H - T - B) * (1 - Math.min(Number(v) || 0, top) / top); };
    var kids = [];

    for (var g = 0; g <= 4; g += 1) {
      var gy = T + (H - T - B) * g / 4;
      kids.push(sv("line", { x1: L, x2: W - RM, y1: gy, y2: gy, class: "chart-grid" }));
      kids.push(sv("text", { x: L - 8, y: gy + 4, "text-anchor": "end", class: "chart-axis" }, [opts.fmt(top * (4 - g) / 4)]));
    }
    for (var k = 0; k <= 3; k += 1) {
      var tt = from + span * k / 3;
      kids.push(sv("text", {
        x: x(tt), y: H - 6, "text-anchor": k === 0 ? "start" : k === 3 ? "end" : "middle", class: "chart-axis"
      }, [timeLabel(tt, span)]));
    }

    // A gap in the samples, the server was down, is a gap in the line and not
    // a straight line across it.
    var step = opts.bucketMs || 60000;
    series.forEach(function (s) {
      var runs = [], run = [];
      points.forEach(function (p, i) {
        if (p[s.key] === null || p[s.key] === undefined) { return; }
        if (run.length && p.t - points[i - 1].t > step * 3) { runs.push(run); run = []; }
        run.push([x(p.t), y(p[s.key])]);
      });
      if (run.length) { runs.push(run); }
      runs.forEach(function (r) {
        var line = r.map(function (xy) { return xy[0].toFixed(1) + "," + xy[1].toFixed(1); }).join(" ");
        if (s.area && r.length > 1) {
          kids.push(sv("polygon", {
            class: "chart-area " + s.cls,
            points: r[0][0].toFixed(1) + "," + y(0) + " " + line + " " + r[r.length - 1][0].toFixed(1) + "," + y(0)
          }));
        }
        kids.push(sv(r.length > 1 ? "polyline" : "circle", r.length > 1
          ? { class: "chart-line " + s.cls, points: line }
          : { class: "chart-dot " + s.cls, cx: r[0][0], cy: r[0][1], r: 2.5 }));
      });
    });

    var cursor = sv("line", { x1: 0, x2: 0, y1: T, y2: H - B, class: "chart-cursor", visibility: "hidden" });
    var dots = series.filter(function (s) { return s.cls !== "c"; }).map(function (s) {
      return sv("circle", { r: 4, class: "chart-dot " + s.cls, visibility: "hidden" });
    });
    var hit = sv("rect", { x: L, y: T, width: W - L - RM, height: H - T - B, fill: "transparent" });
    var sel = sv("rect", { x: L, y: T, width: 0, height: H - T - B, class: "chart-select", visibility: "hidden" });
    kids.push(cursor);
    dots.forEach(function (d) { kids.push(d); });
    if (opts.onSelect) { kids.push(sel); }
    kids.push(hit);

    var svg = sv("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": title }, kids);
    var tip = h("div", { class: "chart-tip" }, []);
    tip.hidden = true;

    function show(clientX) {
      var rect = svg.getBoundingClientRect();
      var sx = (clientX - rect.left) * W / rect.width;
      var t = from + (sx - L) / (W - L - RM) * span;
      var lo = 0, hi = points.length - 1;
      while (hi - lo > 1) {
        var mid = (lo + hi) >> 1;
        if (points[mid].t < t) { lo = mid; } else { hi = mid; }
      }
      var p = Math.abs(points[lo].t - t) <= Math.abs(points[hi].t - t) ? points[lo] : points[hi];
      var px = x(p.t);
      cursor.setAttribute("x1", px); cursor.setAttribute("x2", px); cursor.setAttribute("visibility", "visible");
      series.filter(function (s) { return s.cls !== "c"; }).forEach(function (s, i) {
        dots[i].setAttribute("cx", px); dots[i].setAttribute("cy", y(p[s.key]));
        dots[i].setAttribute("visibility", p[s.key] === null ? "hidden" : "visible");
      });
      clear(tip);
      tip.appendChild(h("div", null, [h("b", null, [new Date(p.t).toLocaleString([], {
        month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
      })])]));
      series.forEach(function (s) {
        tip.appendChild(h("div", null, [h("span", { class: "swatch " + s.cls }, []),
          s.label + ": " + (p[s.key] === null ? "-" : opts.fmt(p[s.key]))]));
      });
      tip.hidden = false;
      var left = (px / W) * rect.width;
      tip.style.left = Math.max(0, Math.min(rect.width - tip.offsetWidth,
        left + 12 > rect.width / 2 ? left - tip.offsetWidth - 12 : left + 12)) + "px";
    }
    function hide() {
      tip.hidden = true;
      cursor.setAttribute("visibility", "hidden");
      dots.forEach(function (d) { d.setAttribute("visibility", "hidden"); });
    }
    hit.addEventListener("mousemove", function (e) { show(e.clientX); });
    hit.addEventListener("mouseleave", hide);
    hit.addEventListener("touchstart", function (e) { if (e.touches[0]) { show(e.touches[0].clientX); } }, { passive: true });
    hit.addEventListener("touchmove", function (e) { if (e.touches[0]) { show(e.touches[0].clientX); } }, { passive: true });
    hit.addEventListener("touchend", hide);

    if (opts.onSelect) {
      var dragFrom = null;
      var svgX = function (clientX) {
        var rect = svg.getBoundingClientRect();
        return Math.max(L, Math.min(W - RM, (clientX - rect.left) * W / rect.width));
      };
      var timeAt = function (sx) { return from + (sx - L) / (W - L - RM) * span; };
      hit.addEventListener("pointerdown", function (e) {
        if (e.pointerType === "mouse" && e.button !== 0) { return; }
        dragFrom = svgX(e.clientX);
        if (hit.setPointerCapture) { hit.setPointerCapture(e.pointerId); }
      });
      hit.addEventListener("pointermove", function (e) {
        if (dragFrom === null) { return; }
        var at = svgX(e.clientX);
        sel.setAttribute("x", Math.min(dragFrom, at));
        sel.setAttribute("width", Math.abs(at - dragFrom));
        sel.setAttribute("visibility", "visible");
      });
      hit.addEventListener("pointerup", function (e) {
        if (dragFrom === null) { return; }
        var at = svgX(e.clientX);
        var a = Math.min(dragFrom, at), b = Math.max(dragFrom, at);
        dragFrom = null;
        sel.setAttribute("visibility", "hidden");
        // A click is not a zoom.
        if (b - a < 6) { return; }
        opts.onSelect(timeAt(a), timeAt(b));
      });
      hit.addEventListener("pointercancel", function () {
        dragFrom = null;
        sel.setAttribute("visibility", "hidden");
      });
    }

    box.appendChild(svg);
    box.appendChild(tip);
    box.appendChild(h("div", { class: "chart-legend" }, series.map(function (s) {
      return h("span", null, [h("span", { class: "swatch " + s.cls }, []), s.label]);
    })));
    return box;
  }

  // The four trends, shared by the page and the one chart tab.
  function charts() {
    return [
      { id: "cpu", title: "CPU", series: [
        { label: "Host", key: "hostCpu", cls: "a", area: true },
        { label: "Git Code Review", key: "appCpu", cls: "b" }
      ], opts: { max: 100, fmt: pct } },
      { id: "memory", title: "Memory", series: [
        { label: "Host used", key: "hostMemUsed", cls: "a", area: true },
        { label: "Git Code Review", key: "appMem", cls: "b" },
        { label: "Host total", key: "hostMemTotal", cls: "c" }
      ], opts: { fmt: bytes } },
      { id: "storage", title: "Storage", series: [
        { label: "Scan disk used", key: "diskUsed", cls: "a", area: true },
        { label: "Disk size", key: "diskTotal", cls: "c" }
      ], opts: { fmt: bytes } },
      { id: "network", title: "Network", series: [
        { label: "In", key: "rxBps", cls: "a", area: true },
        { label: "Out", key: "txBps", cls: "b" }
      ], opts: { fmt: rate } }
    ];
  }

  function chartUrl(id, from, to, live) {
    return PAGE_URL + "?chart=" + id + "&from=" + Math.round(from) + "&to=" + Math.round(to) + (live ? "&live=1" : "");
  }

  function historyUrl(from, to) {
    return HISTORY_URL + "?start=" + Math.round(from) + "&end=" + Math.round(to);
  }

  function params() {
    var out = {};
    new URLSearchParams(window.location.search).forEach(function (v, k) { out[k] = v; });
    return out;
  }

  function hint(text) {
    return h("div", { class: "faint small" }, [text]);
  }

  // One trend on its own.  The window lives in the address, so Back zooms out.
  function viewChart(def, query) {
    var MIN_SPAN = 120000;
    var now = Date.now();
    var num = function (v) { var n = Number(v); return isFinite(n) && n > 0 ? Math.round(n) : null; };
    var live = query.live === "1";
    var to = live ? now : Math.min(num(query.to) || now, now);
    var from = num(query.from);
    if (!from || from >= to) {
      var midnight = new Date();
      midnight.setHours(0, 0, 0, 0);
      from = midnight.getTime();
    }
    if (to - from > 366 * DAY) { from = to - 366 * DAY; }
    if (to - from < MIN_SPAN) { from = to - MIN_SPAN; }

    clear(root);
    root.appendChild(h("div", { class: "page-head" }, [h("div", null, [
      h("h1", null, [def.title + " trend"]),
      hint("Drag across the chart to zoom into that stretch.  Each zoom asks the server again, " +
        "so shorter windows come back with finer points.  The browser Back button zooms back out.")
    ])]));
    var go = function (f, t, isLive) { window.location.href = chartUrl(def.id, f, t, isLive); };
    var local = function (t) { return new Date(t - new Date(t).getTimezoneOffset() * 60000).toISOString().slice(0, 16); };
    var fromIn = h("input", { type: "datetime-local", step: "60", value: local(from) });
    var toIn = h("input", { type: "datetime-local", step: "60", value: local(to) });
    root.appendChild(h("div", { class: "util-range" }, [
      h("label", null, ["From", fromIn]),
      h("label", null, ["To", toIn]),
      h("button", { type: "button", class: "btn", onclick: function () {
        var f = new Date(fromIn.value).getTime();
        var t = new Date(toIn.value).getTime();
        if (!(f < t)) { window.alert("The end has to be after the start."); return; }
        go(f, Math.min(t, Date.now()), false);
      } }, ["Show"]),
      h("button", { type: "button", class: "btn", onclick: function () {
        var width = to - from, centre = from + width / 2;
        var nt = Math.min(Date.now(), centre + width);
        go(Math.max(Date.now() - 366 * DAY, nt - width * 2), nt, nt >= Date.now() - 60000);
      } }, ["Zoom out"]),
      h("button", { type: "button", class: "btn", onclick: function () {
        var m = new Date();
        m.setHours(0, 0, 0, 0);
        go(m.getTime(), Date.now(), true);
      } }, ["Today"])
    ]));
    var info = h("p", { class: "faint small util-window" }, [""]);
    var holder = h("div", { class: "util-single" }, []);
    root.appendChild(info);
    root.appendChild(holder);

    var timer = null;
    function load() {
      if (timer) { clearTimeout(timer); }
      getJson(historyUrl(from, live ? Date.now() : to)).then(function (d) {
        clear(holder);
        holder.appendChild(lineChart(def.title, d.points, def.series, d.from, d.to, Object.assign({
          bucketMs: d.bucketSeconds * 1000,
          big: true,
          onSelect: function (a, b) {
            if (b - a < MIN_SPAN) {
              var c = (a + b) / 2;
              a = c - MIN_SPAN / 2;
              b = c + MIN_SPAN / 2;
            }
            go(a, Math.min(b, Date.now()), false);
          }
        }, def.opts)));
        var each = d.bucketSeconds >= 60
          ? Math.round(d.bucketSeconds / 60) + (d.bucketSeconds === 60 ? " minute" : " minutes")
          : d.bucketSeconds + " seconds";
        info.textContent = new Date(d.from).toLocaleString() + " to " + new Date(d.to).toLocaleString() + ", " +
          d.points.length + " points of " + each + " each" + (live ? ", updating live" : "") + ".";
        if (live) { timer = setTimeout(load, 60000); }
      }).catch(function (e) {
        clear(holder);
        holder.appendChild(notice(e.message));
      });
    }
    load();
  }

  var range = { preset: "today", from: "", to: "" };

  function rangeWindow() {
    var now = Date.now();
    if (range.preset === "custom" && range.from && range.to) {
      var f = range.from.split("-").map(Number);
      var t = range.to.split("-").map(Number);
      var from = new Date(f[0], f[1] - 1, f[2]).getTime();
      var to = Math.min(now, new Date(t[0], t[1] - 1, t[2] + 1).getTime());
      return { from: from, to: Math.max(to, from + 60000) };
    }
    if (range.preset === "week") { return { from: now - 7 * DAY, to: now }; }
    if (range.preset === "month") { return { from: now - 30 * DAY, to: now }; }
    if (range.preset === "year") { return { from: now - 365 * DAY, to: now }; }
    var midnight = new Date();
    midnight.setHours(0, 0, 0, 0);
    return { from: midnight.getTime(), to: now };
  }

  function viewPage() {
    var liveTag = h("span", { class: "util-live" }, ["connecting"]);
    root.appendChild(liveTag);

    var gCpu = gauge("host CPU"), gMem = gauge("host memory"), gDisk = gauge("scan disk");
    var cpuSub = h("p", { class: "util-sub" }, [""]);
    var memSub = h("p", { class: "util-sub" }, [""]);
    var diskSub = h("p", { class: "util-sub" }, [""]);
    var rxNow = h("strong", null, ["-"]), txNow = h("strong", null, ["-"]);
    var netSub = h("p", { class: "util-sub" }, ["Git Code Review traffic"]);
    root.appendChild(h("div", { class: "util-gauges" }, [
      h("div", { class: "util-card" }, [h("h3", null, ["CPU"]), gCpu, cpuSub]),
      h("div", { class: "util-card" }, [h("h3", null, ["Memory"]), gMem, memSub]),
      h("div", { class: "util-card" }, [h("h3", null, ["Storage"]), gDisk, diskSub]),
      h("div", { class: "util-card" }, [h("h3", null, ["Network"]),
        h("div", { class: "util-rate" }, [
          h("div", null, [rxNow, h("span", null, ["in"])]),
          h("div", null, [txNow, h("span", null, ["out"])])
        ]),
        netSub])
    ]));

    var presets = h("div", { class: "presets" }, []);
    var fromIn = h("input", { type: "date", value: range.from });
    var toIn = h("input", { type: "date", value: range.to });
    var names = [["today", "Today"], ["week", "Week"], ["month", "Month"], ["year", "Year"]];
    names.forEach(function (p) {
      presets.appendChild(h("button", {
        type: "button", class: "btn" + (range.preset === p[0] ? " on" : ""),
        onclick: function () { range.preset = p[0]; markPreset(); loadHistory(); }
      }, [p[1]]));
    });
    function markPreset() {
      Array.prototype.forEach.call(presets.children, function (b, i) {
        b.className = "btn" + (names[i][0] === range.preset ? " on" : "");
      });
    }
    root.appendChild(h("div", { class: "util-range" }, [
      presets,
      h("label", null, ["From", fromIn]),
      h("label", null, ["To", toIn]),
      h("button", { type: "button", class: "btn", onclick: function () {
        if (!fromIn.value || !toIn.value) { window.alert("Pick both dates."); return; }
        if (toIn.value < fromIn.value) { window.alert("The end date is before the start date."); return; }
        range = { preset: "custom", from: fromIn.value, to: toIn.value };
        markPreset();
        loadHistory();
      } }, ["Show range"])
    ]));

    var grid = h("div", { class: "util-charts" }, []);
    root.appendChild(grid);

    var lastT = 0, historyTimer = null;

    function paintLive(d) {
      var n = d.now;
      liveTag.className = "util-live" + (n && Date.now() - n.t > d.periodMs * 3 ? " stale" : "");
      liveTag.textContent = n ? "live, updated " + new Date(n.t).toLocaleTimeString() : "waiting for the first sample";
      if (!n) { return; }
      gCpu.update(n.hostCpu);
      cpuSub.textContent = "Git Code Review " + (n.appCores < 0.1 ? n.appCores.toFixed(2) : n.appCores.toFixed(1)) +
        " of " + d.limits.hostCpus + " cores (" + pct(n.appCpu) + ")";
      gMem.update(n.hostMemTotal ? 100 * n.hostMemUsed / n.hostMemTotal : 0);
      memSub.textContent = bytes(n.hostMemUsed) + " of " + bytes(n.hostMemTotal) + ", Git Code Review " + bytes(n.appMem);
      gDisk.update(n.diskTotal ? 100 * n.diskUsed / n.diskTotal : 0);
      var b = d.breakdown || {};
      diskSub.textContent = bytes(n.diskUsed) + " of " + bytes(n.diskTotal) +
        (b.database !== null && b.database !== undefined
          ? ", database " + bytes(b.database) + ", reports " + bytes(b.reports) : "");
      rxNow.textContent = rate(n.rxBps);
      txNow.textContent = rate(n.txBps);
    }

    // Every five seconds, which is how often a sample is taken, and every
    // fifteen when the tab is out of sight.  Users behind one proxy share a
    // rate limit, so polling faster than there is anything new would spend it.
    function pollLive() {
      getJson(LIVE_URL + "?since=" + lastT).then(function (d) {
        if (d.points && d.points.length) { lastT = d.points[d.points.length - 1].t; }
        paintLive(d);
      }).catch(function () {
        liveTag.className = "util-live stale";
        liveTag.textContent = "live figures unavailable, retrying";
      }).then(function () {
        setTimeout(pollLive, document.hidden ? 15000 : 5000);
      });
    }

    function loadHistory() {
      if (historyTimer) { clearTimeout(historyTimer); }
      var w = rangeWindow();
      getJson(historyUrl(w.from, w.to)).then(function (d) {
        var step = d.bucketSeconds * 1000;
        clear(grid);
        var liveRange = Date.now() - d.to < 120000;
        charts().forEach(function (c) {
          grid.appendChild(lineChart(c.title, d.points, c.series, d.from, d.to, Object.assign({
            bucketMs: step,
            open: function () {
              window.open(chartUrl(c.id, d.from, d.to, liveRange), "_blank", "noopener");
            }
          }, c.opts)));
        });
        // A range that ends now keeps moving.
        if (liveRange) { historyTimer = setTimeout(loadHistory, 60000); }
      }).catch(function (e) {
        clear(grid);
        grid.appendChild(notice(e.message));
      });
    }

    pollLive();
    loadHistory();
  }

  var query = params();
  var single = charts().filter(function (c) { return c.id === query.chart; })[0];
  if (single) { viewChart(single, query); } else { viewPage(); }
})();
