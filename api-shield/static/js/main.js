(function () {
  "use strict";

  var q = function (selector, root) {
    return (root || document).querySelector(selector);
  };
  var qa = function (selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  };
  var store = {
    get: function (key) {
      try {
        return window.localStorage.getItem(key);
      } catch (error) {
        return null;
      }
    },
    set: function (key, value) {
      try {
        window.localStorage.setItem(key, value);
      } catch (error) {
        return false;
      }
      return true;
    }
  };

  function toast(message, tone) {
    var stack = q(".toast-stack");
    if (!stack) {
      stack = document.createElement("div");
      stack.className = "toast-stack";
      document.body.appendChild(stack);
    }
    var item = document.createElement("div");
    item.className = "toast";
    item.setAttribute("role", "status");
    item.textContent = message;
    if (tone === "error") {
      item.style.borderColor = "rgba(255, 93, 112, 0.55)";
    }
    stack.appendChild(item);
    window.setTimeout(function () {
      item.classList.add("out");
      window.setTimeout(function () {
        if (item.parentNode) {
          item.parentNode.removeChild(item);
        }
      }, 300);
    }, 4200);
  }

  function initSidebar() {
    var shell = q(".app-shell");
    var collapsed = store.get("apishield:sidebar-collapsed") === "1";
    if (shell && collapsed) {
      shell.classList.add("sidebar-collapsed");
    }

    qa("[data-sidebar-toggle]").forEach(function (button) {
      button.addEventListener("click", function () {
        if (window.matchMedia("(max-width: 980px)").matches) {
          document.body.classList.toggle("sidebar-open");
        } else if (shell) {
          shell.classList.toggle("sidebar-collapsed");
          store.set("apishield:sidebar-collapsed", shell.classList.contains("sidebar-collapsed") ? "1" : "0");
        }
      });
    });

    var scrim = q(".sidebar-scrim");
    if (scrim) {
      scrim.addEventListener("click", function () {
        document.body.classList.remove("sidebar-open");
      });
    }

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        document.body.classList.remove("sidebar-open");
      }
    });
  }

  function initNavState() {
    var links = qa("[data-nav]");
    if (!links.length) {
      return;
    }
    var path = window.location.pathname.replace(/\/+$/, "") || "/";
    var best = null;
    var bestScore = -1;
    links.forEach(function (link) {
      var href = link.getAttribute("href") || "";
      var target = "";
      try {
        target = new URL(href, window.location.origin).pathname.replace(/\/+$/, "") || "/";
      } catch (error) {
        return;
      }
      var matched = target === "/" ? path === "/" : path === target || path.indexOf(target + "/") === 0;
      if (matched && target.length > bestScore) {
        best = link;
        bestScore = target.length;
      }
    });
    if (best) {
      links.forEach(function (link) {
        link.classList.remove("active");
      });
      best.classList.add("active");
    }
  }

  function initDropdowns() {
    qa("[data-dropdown-toggle]").forEach(function (button) {
      button.addEventListener("click", function (event) {
        event.stopPropagation();
        var menu = button.closest(".dropdown");
        if (!menu) {
          return;
        }
        var wasOpen = menu.classList.contains("open");
        qa(".dropdown.open").forEach(function (other) {
          other.classList.remove("open");
        });
        if (!wasOpen) {
          menu.classList.add("open");
        }
      });
    });

    document.addEventListener("click", function (event) {
      qa(".dropdown.open").forEach(function (menu) {
        if (!menu.contains(event.target)) {
          menu.classList.remove("open");
        }
      });
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        qa(".dropdown.open").forEach(function (menu) {
          menu.classList.remove("open");
        });
      }
    });
  }

  function applyTableFilters() {
    qa("[data-searchable-table]").forEach(function (table) {
      var panel = table.closest(".panel") || document;
      var input = q("[data-table-search]", panel);
      var query = input ? input.value.trim().toLowerCase() : "";
      var groups = qa("[data-filter-group]", panel);
      var activeFilters = {};
      groups.forEach(function (group) {
        var key = group.getAttribute("data-filter-key") || "status";
        activeFilters[key] = qa("[data-table-filter].active", group).map(function (pill) {
          return (pill.getAttribute("data-filter-value") || "").toLowerCase();
        });
      });
      var visible = 0;
      qa("tbody tr", table).forEach(function (row) {
        if (row.querySelector("[data-ignore-filter]")) {
          return;
        }
        var text = row.textContent.toLowerCase();
        var passSearch = !query || text.indexOf(query) !== -1;
        var passFilters = true;
        Object.keys(activeFilters).forEach(function (key) {
          var values = activeFilters[key];
          if (!values.length || values.indexOf("all") !== -1) {
            return;
          }
          var cell = q("[data-" + key + "]", row);
          var raw = cell ? (cell.getAttribute("data-" + key) || cell.textContent).trim().toLowerCase() : "";
          if (values.indexOf(raw) === -1) {
            passFilters = false;
          }
        });
        var show = passSearch && passFilters;
        row.hidden = !show;
        if (show) {
          visible += 1;
        }
      });
      var emptyRow = q("[data-table-empty]", table);
      if (emptyRow) {
        emptyRow.hidden = visible !== 0;
      }
    });
  }

  function initTables() {
    qa("[data-table-search]").forEach(function (input) {
      input.addEventListener("input", applyTableFilters);
    });
    qa("[data-table-filter]").forEach(function (pill) {
      pill.addEventListener("click", function () {
        var group = pill.closest("[data-filter-group]");
        var key = pill.getAttribute("data-filter-value") || "all";
        if (key === "all") {
          qa("[data-table-filter]", group).forEach(function (item) {
            item.classList.toggle("active", item === pill);
          });
        } else {
          var all = q('[data-table-filter][data-filter-value="all"]', group);
          if (all) {
            all.classList.remove("active");
          }
          pill.classList.toggle("active");
          if (!qa("[data-table-filter].active", group).length && all) {
            all.classList.add("active");
          }
        }
        applyTableFilters();
      });
    });
    qa("[data-select-all]").forEach(function (master) {
      master.addEventListener("change", function () {
        qa(master.getAttribute("data-select-all")).forEach(function (box) {
          box.checked = master.checked;
        });
      });
    });
    applyTableFilters();
  }

  function copyText(value) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(value);
    }
    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = value;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand("copy");
        resolve();
      } catch (error) {
        reject(error);
      }
      document.body.removeChild(area);
    });
  }

  function initCopyActions() {
    qa("[data-copy], [data-copy-code]").forEach(function (button) {
      button.addEventListener("click", function () {
        var value = button.getAttribute("data-copy-text") || "";
        var target = button.getAttribute("data-copy-target");
        if (target) {
          var field = q(target);
          if (field) {
            value = field.value || field.textContent || "";
          }
        }
        if (button.hasAttribute("data-copy-code")) {
          var block = button.closest(".code-block") || button.parentNode;
          if (block) {
            var code = q("code", block);
            value = code ? code.textContent : block.textContent;
          }
        }
        if (!value) {
          return;
        }
        copyText(value).then(function () {
          toast("Copied to clipboard");
        }).catch(function () {
          toast("Copy failed", "error");
        });
      });
    });

    qa("[data-reveal-secret]").forEach(function (button) {
      button.addEventListener("click", function () {
        var target = q(button.getAttribute("data-reveal-secret") || "");
        if (!target) {
          return;
        }
        var revealed = target.getAttribute("type") === "text";
        target.setAttribute("type", revealed ? "password" : "text");
        button.textContent = revealed ? "Reveal" : "Hide";
      });
    });
  }

  function initForms() {
    qa("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (event) {
        var message = form.getAttribute("data-confirm") || "Are you sure?";
        if (!window.confirm(message)) {
          event.preventDefault();
        }
      });
    });

    qa("[data-file-input]").forEach(function (input) {
      input.addEventListener("change", function () {
        var field = input.closest(".field") || input.parentNode;
        var label = q("[data-file-name]", field);
        if (label) {
          label.textContent = input.files && input.files.length ? input.files[0].name : "No file selected";
        }
      });
    });

    qa(".form-control").forEach(function (control) {
      if (control.value && control.tagName !== "SELECT") {
        control.classList.add("has-value");
      }
      control.addEventListener("blur", function () {
        control.classList.toggle("has-value", Boolean(control.value));
      });
    });
  }

  function initDemoBanner() {
    var banner = q("[data-demo-banner]");
    if (!banner) {
      return;
    }
    if (store.get("apishield:demo-dismissed") === "1") {
      banner.hidden = true;
    }
    var dismiss = q("[data-dismiss-demo]", banner);
    if (dismiss) {
      dismiss.addEventListener("click", function () {
        banner.hidden = true;
        store.set("apishield:demo-dismissed", "1");
      });
    }
  }

  function initRelativeTimes() {
    qa("[data-ago]").forEach(function (node) {
      var raw = node.getAttribute("data-ago") || node.textContent;
      var date = new Date(raw);
      if (isNaN(date.getTime())) {
        return;
      }
      var seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
      var label;
      if (seconds < 60) {
        label = "just now";
      } else if (seconds < 3600) {
        label = Math.floor(seconds / 60) + "m ago";
      } else if (seconds < 86400) {
        label = Math.floor(seconds / 3600) + "h ago";
      } else if (seconds < 2592000) {
        label = Math.floor(seconds / 86400) + "d ago";
      } else {
        label = date.toLocaleDateString();
      }
      node.textContent = label;
      node.setAttribute("title", date.toLocaleString());
    });
  }

  function init() {
    initSidebar();
    initNavState();
    initDropdowns();
    initTables();
    initCopyActions();
    initForms();
    initDemoBanner();
    initRelativeTimes();
    qa("[data-toast]").forEach(function (node) {
      toast(node.textContent.trim(), node.getAttribute("data-tone") || "");
      node.remove();
    });
  }

  window.APIShieldToast = toast;
  document.addEventListener("DOMContentLoaded", init);
})();
