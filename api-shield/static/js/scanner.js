(function () {
  "use strict";

  var STAGES = [
    "Target validation",
    "Endpoint mapping",
    "Security analysis",
    "Report assembly"
  ];

  var STATUS_TARGET = {
    pending: 8,
    queued: 12,
    running: 68,
    active: 68,
    completed: 100,
    success: 100,
    failed: 100,
    cancelled: 100
  };

  var LOG_MESSAGES = [
    ["INFO", "Validating target authorization scope"],
    ["INFO", "Correlating discovered endpoints with specification"],
    ["INFO", "Inspecting authentication requirements"],
    ["WARN", "Elevated exposure detected on administrative route"],
    ["INFO", "Evaluating request and response schemas"],
    ["OK", "Signature set loaded successfully"],
    ["INFO", "Checking transport and header hardening"],
    ["WARN", "Sensitive parameter observed in query string"],
    ["INFO", "Aggregating severity and confidence scores"],
    ["OK", "Evidence bundle prepared for review"]
  ];

  function readScan(host) {
    var inline = window.APISHIELD_SCAN || {};
    return {
      status: host.getAttribute("data-scan-status") || inline.status || "running",
      progress: Number(host.getAttribute("data-scan-progress") || inline.progress || 0),
      live: host.getAttribute("data-live-scan") !== "false"
    };
  }

  function addLog(host, level, message) {
    var log = host.querySelector("[data-scan-log]");
    if (!log) {
      return;
    }
    var line = document.createElement("div");
    line.className = "log-line";
    var time = document.createElement("span");
    time.className = "log-time";
    time.textContent = new Date().toLocaleTimeString("en-GB", { hour12: false });
    var tag = document.createElement("span");
    tag.className = "log-level " + level.toLowerCase();
    tag.textContent = level;
    var text = document.createElement("span");
    text.textContent = message;
    line.appendChild(time);
    line.appendChild(tag);
    line.appendChild(text);
    log.appendChild(line);
    while (log.children.length > 80) {
      log.removeChild(log.firstChild);
    }
    log.scrollTop = log.scrollHeight;
  }

  function buildStages(host) {
    var container = host.querySelector("[data-scan-stages]");
    if (!container || container.children.length) {
      return Array.prototype.slice.call(host.querySelectorAll(".stage"));
    }
    container.innerHTML = "";
    STAGES.forEach(function (name, index) {
      var stage = document.createElement("div");
      stage.className = "stage";
      var indexNode = document.createElement("span");
      indexNode.className = "stage-index";
      indexNode.textContent = "0" + (index + 1);
      var nameNode = document.createElement("span");
      nameNode.className = "stage-name";
      nameNode.textContent = name;
      stage.appendChild(indexNode);
      stage.appendChild(nameNode);
      container.appendChild(stage);
    });
    return Array.prototype.slice.call(container.children);
  }

  function updateStages(stages, progress) {
    var activeIndex = Math.min(STAGES.length - 1, Math.floor((progress / 100) * STAGES.length));
    stages.forEach(function (stage, index) {
      stage.classList.toggle("active", index === activeIndex && progress < 100);
      stage.classList.toggle("done", index < activeIndex || progress >= 100);
    });
  }

  function initHost(host) {
    var config = readScan(host);
    var fill = host.querySelector("[data-progress-fill]");
    var value = host.querySelector("[data-progress-value]");
    var status = host.querySelector("[data-scan-status-text]");
    var elapsed = host.querySelector("[data-scan-elapsed]");
    var stages = buildStages(host);
    var target = STATUS_TARGET[config.status] !== undefined ? STATUS_TARGET[config.status] : config.progress || 68;
    if (config.progress > 0 && config.status !== "completed") {
      target = Math.min(96, Math.max(target, config.progress));
    }
    var current = 0;
    var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var started = Date.now();

    if (status) {
      status.textContent = config.status.replace(/_/g, " ").replace(/\b\w/g, function (letter) {
        return letter.toUpperCase();
      });
    }

    function paint() {
      var rounded = Math.round(current);
      if (fill) {
        fill.style.width = rounded + "%";
      }
      if (value) {
        value.textContent = rounded + "%";
      }
      updateStages(stages, rounded);
      if (rounded >= 100) {
        host.classList.add("is-complete");
        if (status) {
          status.textContent = config.status === "failed" ? "Scan failed" : "Scan completed";
        }
      }
    }

    if (reduced) {
      current = target;
      paint();
    } else {
      function tick() {
        var remaining = target - current;
        if (remaining > 0.35) {
          current += Math.max(0.35, remaining * 0.028);
          paint();
        } else {
          current = target;
          paint();
        }
        if (current < target - 0.1) {
          window.requestAnimationFrame(tick);
        }
      }
      window.setTimeout(function () {
        window.requestAnimationFrame(tick);
      }, 240);
    }

    if (elapsed) {
      window.setInterval(function () {
        var seconds = Math.floor((Date.now() - started) / 1000);
        var minutes = Math.floor(seconds / 60);
        elapsed.textContent = String(minutes).padStart(2, "0") + ":" + String(seconds % 60).padStart(2, "0");
      }, 1000);
    }

    if (config.live && target < 100) {
      var index = 0;
      var timer = window.setInterval(function () {
        var entry = LOG_MESSAGES[index % LOG_MESSAGES.length];
        addLog(host, entry[0], entry[1]);
        index += 1;
        if (index >= LOG_MESSAGES.length || host.classList.contains("is-complete")) {
          window.clearInterval(timer);
        }
      }, 1250);
    }
  }

  function init() {
    var hosts = document.querySelectorAll("[data-scan-progress]");
    Array.prototype.forEach.call(hosts, initHost);
  }

  window.APIShieldScanner = { init: init, log: addLog };
  document.addEventListener("DOMContentLoaded", init);
})();
