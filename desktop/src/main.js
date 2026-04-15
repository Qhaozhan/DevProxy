const invoke = window.__TAURI__?.core?.invoke;

const state = {
  config: null,
  logTimer: null,
  certInstalled: false,
  hostsWritten: false,
  proxyRunning: false,
};

document.addEventListener("DOMContentLoaded", async () => {
  if (!invoke) {
    setNotice("桌面运行时未注入 Tauri API，请重新安装或使用最新构建包。", "error");
    return;
  }
  bindEvents();
  await Promise.all([loadConfig(), loadStatus(), loadLogs(), checkCertState(), checkHostsState()]);
  startLogPolling();
});

function bindEvents() {
  $("#saveConfigBtn").addEventListener("click", saveConfig);
  $("#generateCertsBtn").addEventListener("click", async () => {
    if (state.certInstalled) {
      setNotice("证书已安装，无需重复安装", "success");
      return;
    }
    const result = await call("generate_certs", null, true);
    if (result.ok) {
      await checkCertState();
    }
  });
  $("#deleteCertsBtn").addEventListener("click", async () => {
    await call("delete_certs", null, true);
    state.certInstalled = false;
    updateFlow();
  });

  $("#startProxyBtn").addEventListener("click", () => call("start_proxy", null, true));
  $("#stopProxyBtn").addEventListener("click", () => call("stop_proxy", null, true));
  $("#addHostsBtn").addEventListener("click", async () => {
    const result = await call("add_hosts", null, true);
    if (result.ok) await checkHostsState();
  });
  $("#removeHostsBtn").addEventListener("click", async () => {
    await call("remove_hosts", null, true);
    state.hostsWritten = false;
    updateFlow();
  });
  $("#refreshLogsBtn").addEventListener("click", loadLogs);
  $("#clearLogsBtn").addEventListener("click", clearLogs);
  $("#addRouteBtn").addEventListener("click", () => addRouteCard("", ""));
  $("#advancedToggle").addEventListener("click", () => {
    $("#advancedSection").classList.toggle("collapsed");
  });
}

/* ── Config ─────────────────────────────── */

async function loadConfig() {
  const result = await call("load_config");
  if (!result.ok) {
    // Fill with sensible defaults so the UI isn't empty
    fillForm({
      listen: { host: "127.0.0.1", port: 443 },
      routes: [{ domain: "api.openai.com", upstream: "" }],
      upstream: { timeoutMs: 600000, rejectUnauthorized: true },
      tls: {},
    });
    return;
  }
  state.config = result.data;
  fillForm(result.data);
  updateFlow();
}

function fillForm(config) {
  const routes = config.routes || [];
  const routeList = $("#routeList");
  routeList.innerHTML = "";

  if (routes.length === 0) {
    addRouteCard("api.openai.com", config.upstream?.baseUrl || "");
  } else {
    routes.forEach((r) => addRouteCard(r.domain || "", r.upstream || ""));
  }

  $("#listenHost").value = config.listen?.host || "127.0.0.1";
  $("#listenPort").value = config.listen?.port || 443;
  $("#upstreamTimeoutMs").value = config.upstream?.timeoutMs || 600000;
  $("#rejectUnauthorized").checked = config.upstream?.rejectUnauthorized !== false;
}

function collectForm() {
  const currentTls = state.config?.tls || {};
  const cards = document.querySelectorAll(".route-card");
  const routes = [];
  cards.forEach((card) => {
    const domain = card.querySelector(".route-domain")?.value?.trim();
    const upstream = card.querySelector(".route-upstream")?.value?.trim();
    if (domain) {
      routes.push({ domain, upstream: upstream || "" });
    }
  });

  return {
    listen: {
      host: $("#listenHost").value.trim() || "127.0.0.1",
      port: Number($("#listenPort").value || 443),
    },
    routes,
    upstream: {
      timeoutMs: Number($("#upstreamTimeoutMs").value || 600000),
      rejectUnauthorized: $("#rejectUnauthorized").checked,
    },
    tls: {
      certPath: currentTls.certPath || "",
      keyPath: currentTls.keyPath || "",
    },
    logging: { verbose: true },
  };
}

async function saveConfig() {
  const payload = collectForm();
  if (!payload.routes.length) {
    setNotice("至少需要配置一条路由规则", "error");
    return;
  }
  for (const r of payload.routes) {
    if (!r.domain) {
      setNotice("入口域名不能为空", "error");
      return;
    }
    if (!r.upstream) {
      setNotice(`域名 ${r.domain} 的上游地址不能为空`, "error");
      return;
    }
  }
  const result = await call("save_config", { config: payload }, true);
  if (result.ok) {
    state.config = payload;
    updateFlow();
  }
}

/* ── Route Cards ────────────────────────── */

function addRouteCard(domain, upstream) {
  const routeList = $("#routeList");
  const card = document.createElement("div");
  card.className = "route-card";
  card.innerHTML = `
    <button type="button" class="route-remove" title="删除此路由">×</button>
    <div class="route-row">
      <span class="route-label">域名</span>
      <input class="route-domain" placeholder="api.openai.com" value="${escapeAttr(domain)}" />
    </div>
    <div class="route-row">
      <span class="route-label">上游</span>
      <input class="route-upstream" placeholder="https://proxy-ai.example.com" value="${escapeAttr(upstream)}" />
    </div>
  `;
  card.querySelector(".route-remove").addEventListener("click", () => {
    if (document.querySelectorAll(".route-card").length > 1) {
      card.remove();
    } else {
      setNotice("至少保留一条路由", "error");
    }
  });
  routeList.appendChild(card);
}

/* ── Status ─────────────────────────────── */

async function loadStatus() {
  const result = await call("get_status");
  if (!result.ok) return;
  renderStatus(result.data);
}

function renderStatus(status) {
  const dot = $("#statusDot");
  const text = $("#proxyStatus");
  const pid = $("#proxyPid");

  if (status.running) {
    dot.className = "status-dot running";
    text.className = "status-text running";
    text.textContent = "运行中";
  } else if (status.status === "starting") {
    dot.className = "status-dot starting";
    text.className = "status-text starting";
    text.textContent = "启动中";
  } else if (status.status === "error") {
    dot.className = "status-dot error";
    text.className = "status-text error";
    text.textContent = "异常";
  } else {
    dot.className = "status-dot stopped";
    text.className = "status-text stopped";
    text.textContent = "未启动";
  }
  pid.textContent = `PID: ${status.pid || "-"}`;
  state.proxyRunning = !!status.running;
  updateFlow();
}

/* ── Logs ────────────────────────────────── */

async function loadLogs() {
  const result = await call("get_logs");
  if (!result.ok) return;
  const container = $("#logs");
  container.innerHTML = result.data.length
    ? result.data
        .map(
          (item) =>
            `<div class="log-line"><span style="color:#6cb8ff">[${escapeHtml(item.time)}]</span> <span style="color:${logLevelColor(item.level)}">[${escapeHtml(item.level)}]</span> ${escapeHtml(item.message)}</div>`
        )
        .join("")
    : '<div style="color:#4a5a6a">暂无日志</div>';
  container.scrollTop = container.scrollHeight;
}

function clearLogs() {
  $("#logs").innerHTML = '<div style="color:#4a5a6a">已清空</div>';
  call("clear_logs");
}

function startLogPolling() {
  if (state.logTimer) clearInterval(state.logTimer);
  state.logTimer = setInterval(async () => {
    await Promise.all([loadLogs(), loadStatus()]);
  }, 2000);
}

/* ── Cert State ─────────────────────────── */

async function checkCertState() {
  try {
    const result = await invoke("check_cert_installed", {});
    state.certInstalled = !!(result?.ok && result?.data);
  } catch {
    state.certInstalled = false;
  }
  updateFlow();
}

async function checkHostsState() {
  try {
    const result = await invoke("check_hosts_written", {});
    state.hostsWritten = !!(result?.ok && result?.data);
  } catch {
    state.hostsWritten = false;
  }
  updateFlow();
}

/* ── Flow Guidance ──────────────────────── */

function updateFlow() {
  const hasConfig = !!(state.config?.routes?.some(r => r.domain && r.upstream));
  const certOk = state.certInstalled;
  const hostsOk = state.hostsWritten;
  const running = state.proxyRunning;

  const certBtn = $("#generateCertsBtn");
  if (certBtn) {
    certBtn.textContent = certOk ? "✅ 已安装证书" : "生成证书";
  }

  applyFlow("#saveConfigBtn",    hasConfig                         ? "done"   : "active");
  applyFlow("#generateCertsBtn", certOk                            ? "done"   : (hasConfig  ? "active" : "inactive"));
  applyFlow("#addHostsBtn",      hostsOk                           ? "done"   : (certOk     ? "active" : "inactive"));
  applyFlow("#startProxyBtn",    running                           ? "done"   : (hostsOk    ? "active" : "inactive"));
  applyFlow("#stopProxyBtn",     running                           ? "active" : "inactive");
  applyFlow("#removeHostsBtn",   hostsOk && !running               ? "active" : "inactive");
}

function applyFlow(selector, flowState) {
  const el = document.querySelector(selector);
  if (!el) return;
  el.classList.remove("flow-inactive", "flow-done");
  if (flowState === "inactive") el.classList.add("flow-inactive");
  else if (flowState === "done")     el.classList.add("flow-done");
}

function logLevelColor(level) {
  switch (level) {
    case "ERROR": return "#ff5c5c";
    case "WARN": return "#f5a623";
    case "INFO": return "#00d4aa";
    case "PROXY": return "#c9a0ff";
    default: return "#8b949e";
  }
}

/* ── IPC ─────────────────────────────────── */

async function call(command, payload = {}, refreshAfter = false) {
  try {
    const result = await invoke(command, payload);
    if (!result.ok) {
      setNotice(result.message || `操作失败：${command}`, "error");
    } else if (result.message && command !== "load_config" && command !== "get_status" && command !== "get_logs") {
      setNotice(result.message, "success");
    }
    if (refreshAfter) {
      await Promise.all([loadStatus(), loadLogs()]);
    }
    return result;
  } catch (error) {
    const message = typeof error === "string" ? error : (error?.message || `调用失败：${command}`);
    setNotice(message, "error");
    return { ok: false, message };
  }
}

/* ── Helpers ─────────────────────────────── */

let _noticeTimer = null;
function setNotice(message, type = "info") {
  const notice = $("#notice");
  if (_noticeTimer) { clearTimeout(_noticeTimer); _noticeTimer = null; }
  if (!message) {
    notice.className = "notice hidden";
    notice.textContent = "";
    return;
  }
  notice.className = `notice ${type}`;
  notice.textContent = message;
  _noticeTimer = setTimeout(() => {
    notice.className = "notice hidden";
    notice.textContent = "";
    _noticeTimer = null;
  }, type === "error" ? 8000 : 4000);
}

function $(selector) {
  return document.querySelector(selector);
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function escapeAttr(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}
