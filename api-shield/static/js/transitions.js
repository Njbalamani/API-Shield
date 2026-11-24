(function () {
  "use strict";

  var overlay = null;
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function ensureOverlay() {
    if (overlay) {
      return overlay;
    }
    overlay = document.createElement("div");
    overlay.className = "page-transition";
    overlay.setAttribute("aria-hidden", "true");
    var mark = document.createElement("div");
    mark.className = "transition-mark";
    mark.textContent = "APISHIELD";
    overlay.appendChild(mark);
    document.body.appendChild(overlay);
    return overlay;
  }

  function hideOverlay() {
    if (overlay) {
      overlay.classList.remove("active");
    }
  }

  function isInternal(link, event) {
    if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
      return false;
    }
    if (link.target && link.target !== "_self") {
      return false;
    }
    if (link.hasAttribute("download") || link.hasAttribute("data-no-transition")) {
      return false;
    }
    var href = link.getAttribute("href") || "";
    if (!href || href.charAt(0) === "#" || /^(mailto:|tel:|javascript:|data:)/i.test(href)) {
      return false;
    }
    var url;
    try {
      url = new URL(href, window.location.href);
    } catch (error) {
      return false;
    }
    if (url.origin !== window.location.origin) {
      return false;
    }
    if (url.pathname === window.location.pathname && url.search === window.location.search && url.hash) {
      return false;
    }
    return true;
  }

  function initLinks() {
    if (reduced) {
      return;
    }
    document.addEventListener("click", function (event) {
      var link = event.target.closest("a[href]");
      if (!isInternal(link, event)) {
        return;
      }
      event.preventDefault();
      ensureOverlay().classList.add("active");
      window.setTimeout(function () {
        window.location.assign(link.href);
      }, 190);
    });
  }

  function initEntrance() {
    var main = document.querySelector(".content, .auth-layout, .error-layout");
    if (main && !reduced) {
      main.classList.add("page-enter");
    }
    var targets = document.querySelectorAll("[data-reveal]");
    if (!targets.length) {
      return;
    }
    if (!window.IntersectionObserver || reduced) {
      Array.prototype.forEach.call(targets, function (node) {
        node.classList.add("is-visible");
      });
      return;
    }
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -30px" });
    Array.prototype.forEach.call(targets, function (node) {
      observer.observe(node);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initEntrance();
    initLinks();
  });
  window.addEventListener("pageshow", function (event) {
    if (event.persisted) {
      hideOverlay();
      initEntrance();
    }
  });
  window.addEventListener("popstate", hideOverlay);
})();
