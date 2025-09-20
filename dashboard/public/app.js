const gatewayBase = "/dashboard";
const basePath = window.location.pathname.startsWith(gatewayBase) ? gatewayBase : "";
const apiBase = (basePath || gatewayBase) + "/api";
const oauthBase = (basePath || gatewayBase) + "/oauth2";

const routes = {
  "/audit": renderAudit,
  "/policy": renderPolicy,
};

const toastEl = document.getElementById("toast");
const refreshBtn = document.getElementById("refresh");
const navLinks = document.querySelectorAll('[data-route]');

navLinks.forEach((link) => {
  link.addEventListener("click", (ev) => {
    ev.preventDefault();
    const route = link.dataset.route;
    navigate(route);
  });
});

refreshBtn.addEventListener("click", () => render(true));
window.addEventListener("popstate", () => render());

render(true);

function buildUrl(path) {
  if (!path.startsWith("/")) {
    path = "/" + path;
  }
  if (basePath) {
    return basePath + path;
  }
  return path;
}

async function navigate(path, replace = false) {
  const target = buildUrl(path);
  history[replace ? "replaceState" : "pushState"]({}, "", target);
  await render(true);
}

function currentPath() {
  let path = window.location.pathname;
  if (basePath && path.startsWith(basePath)) {
    path = path.slice(basePath.length);
  }
  if (!path.startsWith("/")) {
    path = "/" + path;
  }
  if (path === "/" || path === "") {
    path = "/audit";
  }
  if (!routes[path]) {
    path = "/audit";
  }
  return path;
}

async function render(forceReload = false) {
  const path = currentPath();
  setActiveLink(path);
  const view = routes[path] || routes["/audit"];
  const root = document.getElementById("app");
  try {
    await view(root, forceReload);
  } catch (err) {
    console.error(err);
    showToast(err.message || "Failed to render", true);
  }
}

function setActiveLink(path) {
  navLinks.forEach((link) => {
    link.classList.toggle("active", link.dataset.route === path);
  });
}

async function apiFetch(path, options = {}) {
  const opts = { ...options, credentials: "include" };
  opts.headers = Object.assign({}, options.headers || {});
  if (opts.body && !opts.headers["Content-Type"]) {
    opts.headers["Content-Type"] = "application/json";
  }
  let url = apiBase + path;
  let res = await fetch(url, opts);
  if (res.status === 404 && basePath === "") {
    url = "/api" + path;
    res = await fetch(url, opts);
  }
  if (res.status === 401 || res.status === 403) {
    window.location.href = `${oauthBase}/start?rd=${encodeURIComponent(window.location.href)}`;
    throw new Error("Authentication required");
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text || "request failed"}`);
  }
  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return res.json();
  }
  return res.text();
}

function showToast(message, isError = false) {
  if (!toastEl) return;
  toastEl.textContent = message;
  toastEl.classList.remove("hidden");
  toastEl.classList.toggle("show", true);
  toastEl.style.borderColor = isError ? "var(--danger)" : "var(--success)";
  toastEl.style.background = isError ? "rgba(231,76,60,0.15)" : "rgba(46,204,113,0.12)";
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => {
    toastEl.classList.remove("show");
    toastEl.classList.add("hidden");
  }, 3200);
}

async function renderAudit(root) {
  root.innerHTML = `
    <section class="card">
      <h2>Latest Agent Findings</h2>
      <form id="filters" class="filters">
        <input id="filter-host" name="host" placeholder="Hostname" autocomplete="off" />
        <input id="filter-q" name="q" placeholder="Policy / keyword" autocomplete="off" />
        <input id="filter-from" name="from" type="date" />
        <input id="filter-to" name="to" type="date" />
        <button type="submit" class="primary">Apply</button>
        <button type="button" id="filters-clear" class="secondary">Clear</button>
      </form>
    </section>
    <section class="card table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Host</th>
            <th>Policy</th>
            <th>Status</th>
            <th>Expected</th>
            <th>Reason</th>
            <th>Fix</th>
          </tr>
        </thead>
        <tbody id="results-body">
          <tr><td colspan="7">Loading results...</td></tr>
        </tbody>
      </table>
    </section>
  `;

  const form = document.getElementById("filters");
  const tbody = document.getElementById("results-body");
  const clearBtn = document.getElementById("filters-clear");

  const load = async () => {
    const fd = new FormData(form);
    const params = new URLSearchParams();
    for (const [key, value] of fd.entries()) {
      const trimmed = String(value).trim();
      if (trimmed) params.set(key, trimmed);
    }
    try {
      tbody.innerHTML = `<tr><td colspan="7">Loading results...</td></tr>`;
      const qs = params.toString();
      const data = await apiFetch(qs ? `/results?${qs}` : "/results");
      if (!Array.isArray(data) || data.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7">No results yet.</td></tr>`;
        return;
      }
      tbody.innerHTML = data
        .map((row) => `
          <tr class="status-${(row.status || "").toUpperCase()}">
            <td>${escapeHtml(row.time)}</td>
            <td>${escapeHtml(row.host)}</td>
            <td>${escapeHtml(row.policy)}</td>
            <td><span class="badge ${row.status === "FAIL" ? "danger" : "ok"}">${escapeHtml(row.status)}</span></td>
            <td><pre>${escapeHtml(row.expected)}</pre></td>
            <td><pre>${escapeHtml(row.reason)}</pre></td>
            <td><pre>${escapeHtml(row.fix)}</pre></td>
          </tr>
        `)
        .join("");
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="7">${escapeHtml(err.message || "Failed to load results")}</td></tr>`;
      showToast(err.message || "Failed to load results", true);
    }
  };

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    load();
  });

  clearBtn.addEventListener("click", () => {
    form.reset();
    load();
  });

  await load();
}

async function renderPolicy(root) {
  root.innerHTML = `
    <section class="card" id="policy-active">
      <h2>Active Policy</h2>
      <div class="meta" id="policy-meta">Loading...</div>
      <textarea id="policy-editor" spellcheck="false" placeholder="Policy YAML"></textarea>
      <div class="actions">
        <button type="button" id="policy-save" class="primary">Save as new version</button>
        <button type="button" id="policy-reset" class="secondary">Reset changes</button>
      </div>
    </section>
    <section class="card" id="policy-history">
      <h2>Policy Versions</h2>
      <div class="history-controls">
        <label for="history-select">Activate version:</label>
        <select id="history-select"></select>
        <button type="button" id="history-activate" class="secondary">Activate</button>
      </div>
      <div class="table-wrapper">
        <table>
          <thead>
            <tr><th>Version</th><th>Hash</th><th>Updated</th></tr>
          </thead>
          <tbody id="history-body"><tr><td colspan="3">Loading history...</td></tr></tbody>
        </table>
      </div>
    </section>
  `;

  const metaEl = document.getElementById("policy-meta");
  const editor = document.getElementById("policy-editor");
  const saveBtn = document.getElementById("policy-save");
  const resetBtn = document.getElementById("policy-reset");
  const historyBody = document.getElementById("history-body");
  const historySelect = document.getElementById("history-select");
  const activateBtn = document.getElementById("history-activate");

  let activePolicy = null;
  let history = [];

  try {
    [activePolicy, history] = await Promise.all([
      apiFetch("/policy/active"),
      apiFetch("/policy/history"),
    ]);
  } catch (err) {
    const message = err.message || "Unable to load policy";
    metaEl.textContent = message;
    historyBody.innerHTML = `<tr><td colspan="3">${escapeHtml(message)}</td></tr>`;
    showToast(message, true);
    return;
  }

  editor.value = activePolicy?.yaml || "";
  metaEl.textContent = activePolicy
    ? `Policy ${activePolicy.policy_id} � version ${activePolicy.version} � hash ${activePolicy.hash}`
    : "No active policy";

  if (history.length) {
    historySelect.innerHTML = history
      .map(
        (item) => `
          <option value="${item.policy_id}:${item.version}" ${item.version === activePolicy?.version ? "selected" : ""}>
            ${item.policy_id} � v${item.version} � ${new Date(item.updated).toLocaleString()}
          </option>`
      )
      .join("");
  } else {
    historySelect.innerHTML = `<option value="">No history yet</option>`;
  }

  historyBody.innerHTML = history.length
    ? history
        .map(
          (item) => `
            <tr>
              <td>${item.version}</td>
              <td><code>${escapeHtml(item.hash)}</code></td>
              <td>${new Date(item.updated).toLocaleString()}</td>
            </tr>`
        )
        .join("")
    : `<tr><td colspan="3">No versions recorded.</td></tr>`;

  const resetEditor = () => {
    editor.value = activePolicy?.yaml || "";
  };

  saveBtn.addEventListener("click", async () => {
    const yaml = editor.value.trim();
    if (!yaml) {
      showToast("Policy YAML cannot be empty", true);
      return;
    }
    try {
      const result = await apiFetch("/policy/save", {
        method: "POST",
        body: JSON.stringify({ yaml }),
      });
      showToast(`Policy version ${result.version} stored`);
      await renderPolicy(root);
    } catch (err) {
      showToast(err.message || "Failed to save policy", true);
    }
  });

  resetBtn.addEventListener("click", resetEditor);

  activateBtn.addEventListener("click", async () => {
    const value = historySelect.value;
    if (!value) {
      showToast("Select a version to activate", true);
      return;
    }
    const [policyId, version] = value.split(":");
    try {
      await apiFetch("/policy/activate", {
        method: "POST",
        body: JSON.stringify({ policy_id: policyId, version: Number(version) }),
      });
      showToast(`Activated ${policyId} v${version}`);
      await renderPolicy(root);
    } catch (err) {
      showToast(err.message || "Failed to activate policy", true);
    }
  });
}

function escapeHtml(input) {
  if (input === null || input === undefined) return "";
  return String(input).replace(/[&<>\"]/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
  })[c] || c);
}
