(function () {
  "use strict";

  var COLORS = {
    critical: "#ff5d70",
    high: "#ff9b4a",
    medium: "#f0c751",
    low: "#55b8ff",
    info: "#8ea6c8",
    none: "#4b638c"
  };

  function readJson(node) {
    if (!node || !node.textContent) {
      return null;
    }
    try {
      return JSON.parse(node.textContent);
    } catch (error) {
      return null;
    }
  }

  function getMetrics() {
    var inline = readJson(document.getElementById("apishield-metrics-data"));
    return window.APISHIELD_METRICS || inline || {};
  }

  function severityEntries(metrics) {
    var source = metrics.severity || metrics.severity_counts || {};
    var entries;
    if (Array.isArray(source)) {
      entries = source.map(function (item) {
        if (typeof item === "object" && item !== null) {
          return [item.name || item.label || item.severity || "info", Number(item.value || item.count || 0)];
        }
        return [String(item), 0];
      });
    } else {
      entries = Object.keys(source).map(function (key) {
        return [key, Number(source[key]) || 0];
      });
    }
    if (!entries.length) {
      entries = [
        ["critical", 4], ["high", 9], ["medium", 18], ["low", 27], ["info", 12]
      ];
    }
    return entries;
  }

  function trendEntries(metrics) {
    var source = metrics.trend || metrics.findings_trend || metrics.activity_trend || [];
    if (!Array.isArray(source) || !source.length) {
      var days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
      return days.map(function (day, index) {
        return { label: day, value: [8, 14, 10, 19, 15, 24, 17][index] };
      });
    }
    return source.map(function (item, index) {
      if (typeof item === "object" && item !== null) {
        return {
          label: item.label || item.date || item.day || "T" + (index + 1),
          value: Number(item.value !== undefined ? item.value : item.count || 0) || 0
        };
      }
      return { label: "T" + (index + 1), value: Number(item) || 0 };
    });
  }

  function colorFor(key) {
    return COLORS[String(key).toLowerCase()] || "#9aa8c4";
  }

  function applyTheme() {
    if (!window.Chart) {
      return null;
    }
    window.Chart.defaults.color = "#8394b3";
    window.Chart.defaults.font.family = "Inter, Segoe UI, sans-serif";
    window.Chart.defaults.font.size = 11;
    window.Chart.defaults.plugins.legend.display = false;
    window.Chart.defaults.plugins.tooltip.backgroundColor = "rgba(6, 12, 24, 0.95)";
    window.Chart.defaults.plugins.tooltip.borderColor = "rgba(212, 175, 55, 0.35)";
    window.Chart.defaults.plugins.tooltip.borderWidth = 1;
    window.Chart.defaults.plugins.tooltip.titleColor = "#f4d878";
    window.Chart.defaults.plugins.tooltip.bodyColor = "#c2cde1";
    window.Chart.defaults.plugins.tooltip.padding = 12;
    window.Chart.defaults.plugins.tooltip.cornerRadius = 10;
    return window.Chart;
  }

  function fallbackBars(canvas, entries) {
    var frame = canvas.closest(".chart-frame");
    if (!frame) {
      return;
    }
    frame.classList.add("no-canvas");
    var host = frame.querySelector(".chart-fallback");
    if (!host) {
      host = document.createElement("div");
      host.className = "chart-fallback";
      frame.appendChild(host);
    }
    var max = Math.max.apply(null, entries.map(function (entry) { return entry[1]; }).concat([1]));
    host.innerHTML = "";
    entries.forEach(function (entry) {
      var row = document.createElement("div");
      row.className = "fallback-bar";
      var name = document.createElement("span");
      name.textContent = entry[0];
      var track = document.createElement("div");
      track.className = "fallback-track";
      var fill = document.createElement("span");
      fill.style.width = Math.round((entry[1] / max) * 100) + "%";
      fill.style.background = colorFor(entry[0]);
      track.appendChild(fill);
      var value = document.createElement("span");
      value.className = "text-mono";
      value.textContent = entry[1];
      row.appendChild(name);
      row.appendChild(track);
      row.appendChild(value);
      host.appendChild(row);
    });
  }

  function initSeverity(canvas, metrics) {
    if (!canvas) {
      return;
    }
    var entries = severityEntries(metrics);
    var labels = entries.map(function (entry) { return String(entry[0]).replace(/_/g, " "); });
    var values = entries.map(function (entry) { return entry[1]; });
    var colors = entries.map(function (entry) { return colorFor(entry[0]); });
    var Chart = applyTheme();
    if (!Chart) {
      fallbackBars(canvas, entries);
      return;
    }
    new Chart(canvas, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderColor: "rgba(5, 10, 20, 0.9)",
          borderWidth: 3,
          hoverOffset: 10
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "73%",
        animation: { animateScale: true, duration: 900 },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: function (context) {
            return " " + context.label + ": " + context.parsed;
          } } }
        }
      }
    });
    var center = document.getElementById("severity-center");
    if (center) {
      var total = values.reduce(function (sum, value) { return sum + value; }, 0);
      var strong = center.querySelector("strong");
      if (strong) {
        strong.textContent = total;
      }
    }
  }

  function initTrend(canvas, metrics) {
    if (!canvas) {
      return;
    }
    var entries = trendEntries(metrics);
    var Chart = applyTheme();
    if (!Chart) {
      fallbackBars(canvas, entries.map(function (entry) { return [entry.label, entry.value]; }));
      return;
    }
    var context = canvas.getContext("2d");
    var gradient = context.createLinearGradient(0, 0, 0, 260);
    gradient.addColorStop(0, "rgba(212, 175, 55, 0.38)");
    gradient.addColorStop(1, "rgba(212, 175, 55, 0.01)");
    new Chart(canvas, {
      type: "line",
      data: {
        labels: entries.map(function (entry) { return entry.label; }),
        datasets: [
          {
            label: "Findings",
            data: entries.map(function (entry) { return entry.value; }),
            borderColor: "#d4af37",
            backgroundColor: gradient,
            borderWidth: 2,
            pointBackgroundColor: "#f4d878",
            pointBorderColor: "#0a1224",
            pointBorderWidth: 2,
            pointRadius: 4,
            pointHoverRadius: 6,
            tension: 0.38,
            fill: true
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: "index" },
        scales: {
          x: {
            grid: { color: "rgba(154, 178, 220, 0.07)", drawBorder: false },
            ticks: { color: "#7f90ad" }
          },
          y: {
            beginAtZero: true,
            grid: { color: "rgba(154, 178, 220, 0.07)", drawBorder: false },
            ticks: { color: "#7f90ad", precision: 0 }
          }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  function initRisk(canvas, metrics) {
    if (!canvas) {
      return;
    }
    var source = metrics.endpoint_risk || metrics.risk || {};
    var entries = Object.keys(source).map(function (key) {
      return [key.replace(/_/g, " "), Number(source[key]) || 0];
    });
    if (!entries.length) {
      entries = [["Public", 14], ["Authenticated", 22], ["Admin", 7], ["Payment", 5]];
    }
    var Chart = applyTheme();
    if (!Chart) {
      fallbackBars(canvas, entries);
      return;
    }
    new Chart(canvas, {
      type: "bar",
      data: {
        labels: entries.map(function (entry) { return entry[0]; }),
        datasets: [{
          label: "Endpoints",
          data: entries.map(function (entry) { return entry[1]; }),
          backgroundColor: entries.map(function (entry, index) {
            return index % 2 === 0 ? "rgba(212, 175, 55, 0.75)" : "rgba(66, 116, 194, 0.75)";
          }),
          borderRadius: 6,
          barThickness: 18
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            beginAtZero: true,
            grid: { color: "rgba(154, 178, 220, 0.07)", drawBorder: false },
            ticks: { color: "#7f90ad", precision: 0 }
          },
          y: {
            grid: { display: false, drawBorder: false },
            ticks: { color: "#aab8d2" }
          }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  function init() {
    var metrics = getMetrics();
    initSeverity(document.getElementById("severity-chart"), metrics);
    initTrend(document.getElementById("trend-chart"), metrics);
    initRisk(document.getElementById("risk-chart"), metrics);
    qa("[data-severity-list]").forEach(function (list) {
      var entries = severityEntries(metrics);
      var max = Math.max.apply(null, entries.map(function (entry) { return entry[1]; }).concat([1]));
      list.innerHTML = "";
      entries.forEach(function (entry) {
        var key = String(entry[0]).toLowerCase();
        var row = document.createElement("div");
        row.className = "severity-row text-" + key;
        var label = document.createElement("span");
        label.textContent = key.replace(/_/g, " ");
        var track = document.createElement("div");
        track.className = "severity-track";
        var fill = document.createElement("span");
        fill.style.width = Math.round((entry[1] / max) * 100) + "%";
        track.appendChild(fill);
        var value = document.createElement("span");
        value.className = "text-mono";
        value.textContent = entry[1];
        row.appendChild(label);
        row.appendChild(track);
        row.appendChild(value);
        list.appendChild(row);
      });
    });
  }

  window.APIShieldCharts = { init: init };
  document.addEventListener("DOMContentLoaded", init);
  document.addEventListener("apishield:metrics", init);
})();
