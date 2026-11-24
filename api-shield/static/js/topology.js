(function () {
  "use strict";

  var RISK_COLORS = {
    critical: 0xff5d70,
    high: 0xff9b4a,
    medium: 0xf0c751,
    low: 0x55b8ff,
    info: 0x8ea6c8,
    none: 0x4b638c
  };

  var DEFAULT_TOPOLOGY = {
    nodes: [
      { id: "gateway", label: "API Gateway", type: "gateway", risk: "low" },
      { id: "auth", label: "Auth Service", type: "service", risk: "high" },
      { id: "users", label: "Users API", type: "endpoint", risk: "medium" },
      { id: "payments", label: "Payments API", type: "endpoint", risk: "critical" },
      { id: "orders", label: "Orders API", type: "endpoint", risk: "low" },
      { id: "inventory", label: "Inventory API", type: "endpoint", risk: "medium" },
      { id: "webhook", label: "Webhooks", type: "service", risk: "high" },
      { id: "analytics", label: "Analytics", type: "service", risk: "low" },
      { id: "admin", label: "Admin Console", type: "endpoint", risk: "critical" },
      { id: "storage", label: "Object Storage", type: "store", risk: "info" }
    ],
    links: [
      { source: "gateway", target: "auth" },
      { source: "gateway", target: "users" },
      { source: "gateway", target: "payments" },
      { source: "gateway", target: "orders" },
      { source: "gateway", target: "inventory" },
      { source: "auth", target: "admin" },
      { source: "auth", target: "webhook" },
      { source: "orders", target: "analytics" },
      { source: "payments", target: "storage" },
      { source: "webhook", target: "analytics" },
      { source: "users", target: "storage" }
    ]
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

  function getData(host) {
    var attribute = host.getAttribute("data-topology");
    var inline = null;
    if (attribute) {
      try {
        inline = JSON.parse(attribute);
      } catch (error) {
        inline = null;
      }
    }
    return window.APISHIELD_TOPOLOGY || readJson(document.getElementById("apishield-topology-data")) || inline || DEFAULT_TOPOLOGY;
  }

  function normalize(data) {
    var rawNodes = data.nodes || data.endpoints || [];
    var rawLinks = data.links || data.edges || data.connections || [];
    var nodes = rawNodes.map(function (item, index) {
      if (typeof item === "string") {
        item = { id: item, label: item };
      }
      var phi = Math.acos(1 - (2 * (index + 0.5)) / Math.max(rawNodes.length, 1));
      var theta = Math.PI * (1 + Math.sqrt(5)) * index;
      var radius = 34;
      return {
        id: String(item.id !== undefined ? item.id : index),
        label: item.label || item.name || item.path || ("Node " + (index + 1)),
        type: item.type || "endpoint",
        risk: String(item.risk || item.risk_level || "none").toLowerCase(),
        x: Number(item.x !== undefined ? item.x : radius * Math.sin(phi) * Math.cos(theta)),
        y: Number(item.y !== undefined ? item.y : radius * Math.cos(phi)),
        z: Number(item.z !== undefined ? item.z : radius * Math.sin(phi) * Math.sin(theta))
      };
    });
    var ids = nodes.map(function (node) { return node.id; });
    var links = rawLinks.map(function (item) {
      if (Array.isArray(item)) {
        item = { source: item[0], target: item[1] };
      }
      return {
        source: String(item.source !== undefined ? item.source : item.from),
        target: String(item.target !== undefined ? item.target : item.to),
        risk: String(item.risk || (ids.indexOf(String(item.source)) === 0 ? "medium" : "low")).toLowerCase()
      };
    }).filter(function (link) {
      return ids.indexOf(link.source) !== -1 && ids.indexOf(link.target) !== -1;
    });
    if (!nodes.length) {
      return DEFAULT_TOPOLOGY;
    }
    return { nodes: nodes, links: links };
  }

  function riskHex(risk) {
    return RISK_COLORS[risk] !== undefined ? RISK_COLORS[risk] : RISK_COLORS.info;
  }

  function riskLabel(risk) {
    return String(risk || "none").replace(/_/g, " ").replace(/\b\w/g, function (letter) {
      return letter.toUpperCase();
    });
  }

  function showTooltip(host, tooltip, node, event) {
    var name = tooltip.querySelector("strong");
    var meta = tooltip.querySelector("span");
    if (name) {
      name.textContent = node.label;
    }
    if (meta) {
      meta.textContent = riskLabel(node.risk) + " / " + node.type.replace(/_/g, " ");
    }
    var rect = host.getBoundingClientRect();
    tooltip.style.left = (event.clientX - rect.left) + "px";
    tooltip.style.top = (event.clientY - rect.top) + "px";
    tooltip.classList.add("visible");
  }

  function renderFallback(host, data, tooltip) {
    host.classList.add("no-webgl");
    var layer = host.querySelector(".network-fallback");
    if (!layer) {
      return;
    }
    layer.innerHTML = "";
    var width = host.clientWidth || 800;
    var height = host.clientHeight || 400;
    var positions = {};
    data.nodes.forEach(function (node, index) {
      var angle = (index / Math.max(data.nodes.length, 1)) * Math.PI * 2;
      var ring = index % 3 === 0 ? 0.22 : 0.35;
      positions[node.id] = {
        x: width / 2 + Math.cos(angle) * width * ring,
        y: height / 2 + Math.sin(angle) * height * ring
      };
    });
    data.links.forEach(function (link) {
      var from = positions[link.source];
      var to = positions[link.target];
      if (!from || !to) {
        return;
      }
      var dx = to.x - from.x;
      var dy = to.y - from.y;
      var line = document.createElement("div");
      line.className = "fallback-edge";
      line.style.left = from.x + "px";
      line.style.top = from.y + "px";
      line.style.width = Math.sqrt(dx * dx + dy * dy) + "px";
      line.style.transform = "rotate(" + Math.atan2(dy, dx) + "rad)";
      layer.appendChild(line);
    });
    data.nodes.forEach(function (node) {
      var dot = document.createElement("div");
      var point = positions[node.id];
      dot.className = "fallback-node";
      dot.style.left = point.x + "px";
      dot.style.top = point.y + "px";
      dot.style.background = "#" + riskHex(node.risk).toString(16).padStart(6, "0");
      dot.style.color = dot.style.background;
      dot.title = node.label + " / " + riskLabel(node.risk);
      dot.addEventListener("mousemove", function (event) {
        showTooltip(host, tooltip, node, event);
      });
      dot.addEventListener("mouseleave", function () {
        tooltip.classList.remove("visible");
      });
      layer.appendChild(dot);
    });
  }

  function init() {
    var hosts = qa("[data-network-visual]");
    if (!hosts.length && document.getElementById("network-visual")) {
      hosts = [document.getElementById("network-visual")];
    }
    hosts.forEach(function (host) {
      var data = normalize(getData(host));
      var tooltip = host.querySelector(".network-tooltip") || document.createElement("div");
      if (!tooltip.parentNode) {
        tooltip.className = "network-tooltip";
        host.appendChild(tooltip);
      }
      if (!window.THREE) {
        renderFallback(host, data, tooltip);
        return;
      }

      var scene, renderer, camera;
      try {
        scene = new THREE.Scene();
        scene.fog = new THREE.FogExp2(0x040811, 0.0062);
        camera = new THREE.PerspectiveCamera(52, 1, 0.1, 600);
        camera.position.set(0, 22, 112);
        renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: "high-performance" });
        renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
        renderer.setClearColor(0x000000, 0);
      } catch (error) {
        renderFallback(host, data, tooltip);
        return;
      }

      var width = host.clientWidth || 800;
      var height = host.clientHeight || 400;
      renderer.setSize(width, height, false);
      host.insertBefore(renderer.domElement, host.firstChild);

      scene.add(new THREE.AmbientLight(0x6d8fca, 0.75));
      var keyLight = new THREE.PointLight(0xd4af37, 1.35, 260);
      keyLight.position.set(40, 50, 70);
      scene.add(keyLight);
      var rimLight = new THREE.PointLight(0x2f6fdf, 1.1, 260);
      rimLight.position.set(-60, -30, 40);
      scene.add(rimLight);

      var group = new THREE.Group();
      scene.add(group);

      var grid = new THREE.GridHelper(220, 22, 0x1a3a68, 0x0d1b33);
      grid.position.y = -46;
      grid.material.transparent = true;
      grid.material.opacity = 0.32;
      scene.add(grid);

      var core = new THREE.Mesh(
        new THREE.IcosahedronGeometry(5.4, 2),
        new THREE.MeshStandardMaterial({
          color: 0xd4af37,
          emissive: 0x8a6819,
          emissiveIntensity: 0.85,
          metalness: 0.8,
          roughness: 0.24,
          wireframe: true,
          transparent: true,
          opacity: 0.9
        })
      );
      group.add(core);

      var ring = new THREE.Mesh(
        new THREE.TorusGeometry(13, 0.12, 8, 96),
        new THREE.MeshBasicMaterial({ color: 0xd4af37, transparent: true, opacity: 0.35 })
      );
      ring.rotation.x = Math.PI / 2.4;
      group.add(ring);

      var nodeGeometry = new THREE.SphereGeometry(2.5, 18, 18);
      var shellGeometry = new THREE.IcosahedronGeometry(4.2, 1);
      var particleGeometry = new THREE.SphereGeometry(0.65, 8, 8);
      var nodeMeshes = [];
      var positionsById = {};

      data.nodes.forEach(function (node) {
        var color = riskHex(node.risk);
        var point = new THREE.Vector3(node.x, node.y, node.z);
        positionsById[node.id] = point;
        var mesh = new THREE.Mesh(
          nodeGeometry,
          new THREE.MeshStandardMaterial({
            color: color,
            emissive: color,
            emissiveIntensity: 0.65,
            metalness: 0.55,
            roughness: 0.28
          })
        );
        mesh.position.copy(point);
        mesh.userData = { node: node, baseScale: 1 };
        group.add(mesh);
        nodeMeshes.push(mesh);
        var shell = new THREE.Mesh(
          shellGeometry,
          new THREE.MeshBasicMaterial({ color: color, wireframe: true, transparent: true, opacity: 0.16 })
        );
        shell.position.copy(point);
        mesh.userData.shell = shell;
        group.add(shell);
      });

      var particleMaterial = new THREE.MeshBasicMaterial({ color: 0xf4d878, transparent: true, opacity: 0.95 });
      var particles = [];
      data.links.forEach(function (link, index) {
        var start = positionsById[link.source];
        var end = positionsById[link.target];
        if (!start || !end) {
          return;
        }
        var color = riskHex(link.risk);
        var geometry = new THREE.BufferGeometry().setFromPoints([start, end]);
        var line = new THREE.Line(
          geometry,
          new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: 0.34 })
        );
        group.add(line);
        var particle = new THREE.Mesh(particleGeometry, particleMaterial.clone());
        particle.material.color.setHex(color === RISK_COLORS.none ? 0xf4d878 : color);
        group.add(particle);
        particles.push({
          mesh: particle,
          from: start.clone(),
          to: end.clone(),
          progress: (index * 0.137) % 1,
          speed: 0.0016 + (index % 5) * 0.00035
        });
      });

      var raycaster = new THREE.Raycaster();
      var pointer = new THREE.Vector2(-10, -10);
      var hovered = null;
      var pointerInside = false;
      var targetRotation = 0;
      var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

      host.addEventListener("pointermove", function (event) {
        var rect = renderer.domElement.getBoundingClientRect();
        pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
        pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
        targetRotation = pointer.x * 0.16;
        pointerInside = true;
      });
      host.addEventListener("pointerleave", function () {
        pointer.set(-10, -10);
        pointerInside = false;
        tooltip.classList.remove("visible");
      });

      function resize() {
        var w = host.clientWidth || 800;
        var h = host.clientHeight || 400;
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        renderer.setSize(w, h, false);
      }
      if (window.ResizeObserver) {
        new ResizeObserver(resize).observe(host);
      } else {
        window.addEventListener("resize", resize);
      }
      resize();

      var visible = true;
      if (window.IntersectionObserver) {
        new IntersectionObserver(function (entries) {
          visible = entries[0].isIntersecting;
        }, { threshold: 0.05 }).observe(host);
      }

      var start = performance.now();
      function frame(now) {
        var elapsed = now - start;
        if (visible && !document.hidden) {
          if (!reduced) {
            group.rotation.y += 0.0009 + (pointerInside ? targetRotation * 0.008 : 0);
            ring.rotation.z += 0.003;
            core.rotation.x += 0.002;
            core.rotation.y -= 0.0015;
          }
          raycaster.setFromCamera(pointer, camera);
          var hits = raycaster.intersectObjects(nodeMeshes, false);
          var hit = hits.length ? hits[0].object : null;
          if (hit !== hovered) {
            if (hovered) {
              hovered.scale.setScalar(1);
            }
            hovered = hit;
            if (hovered) {
              hovered.scale.setScalar(1.45);
              showTooltip(host, tooltip, hovered.userData.node, lastPointerEvent || { clientX: 0, clientY: 0 });
            } else {
              tooltip.classList.remove("visible");
            }
          } else if (hovered && lastPointerEvent) {
            showTooltip(host, tooltip, hovered.userData.node, lastPointerEvent);
          }
          particles.forEach(function (particle) {
            particle.progress += particle.speed;
            if (particle.progress > 1) {
              particle.progress -= 1;
            }
            particle.mesh.position.lerpVectors(particle.from, particle.to, particle.progress);
            if (!reduced) {
              particle.mesh.scale.setScalar(0.8 + Math.sin(elapsed * 0.004 + particle.progress * 8) * 0.25);
            }
          });
          renderer.render(scene, camera);
        }
        window.requestAnimationFrame(frame);
      }
      var lastPointerEvent = null;
      host.addEventListener("pointermove", function (event) {
        lastPointerEvent = event;
      });
      window.requestAnimationFrame(frame);
    });
  }

  function qa(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  window.APIShieldTopology = { init: init };
  document.addEventListener("DOMContentLoaded", init);
  document.addEventListener("apishield:topology", init);
})();
