"use strict";

const $ = (selector) => document.querySelector(selector);
const envNames = { DEV: "开发环境", STG: "预发环境", PROD: "生产环境" };
const grantNames = { diagnose: "限时诊断", retry: "单次重跑" };
const statusNames = { pending: "待审批", approved: "已授权", denied: "已拒绝", revoked: "已收回", expired: "已过期", consumed: "已使用" };
const events = { switch: "切换环境", request: "申请权限", approve: "批准申请", deny: "拒绝申请", use: "使用权限", admit: "受理单次操作", revoke: "收回权限", read: "读取服务状态", expire: "临时授权到期", startup: "服务启动", end: "结束会话", outcome: "查询上游回执", "sdk-session": "签发 SDK 会话", "sdk-revoke":"收回 SDK 会话", "sdk-close":"SDK 会话结束", "sdk_read":"SDK 读取" };
const resultNames = { allowed: "允许", denied: "拒绝", failed: "失败" };
const pageSize = 30;
const formatter = new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const formatTime = (value) => Number.isFinite(Number(value)) ? formatter.format(new Date(Number(value))) : "—";
const node = (tag, value, cls) => {
  const el = document.createElement(tag);
  if (value !== undefined) el.textContent = value;
  if (cls) el.className = cls;
  return el;
};

const fragment = new URLSearchParams(location.hash.slice(1));
const incoming = fragment.get("access");
if (incoming !== null) history.replaceState(null, "", location.pathname + location.search);
let access = incoming;
try {
  if (incoming) sessionStorage.setItem("keyheron-session", incoming);
  else {
    access = sessionStorage.getItem("keyheron-session") || sessionStorage.getItem("agent-access-key");
    if (access) sessionStorage.setItem("keyheron-session", access);
  }
  sessionStorage.removeItem("agent-access-key");
} catch { /* The initial link still works when storage is disabled. */ }

let state = null;
let rows = [];
let hasOlder = false;
let paging = false;
let busy = false;
let liveRevision = 0;
let eventRevision = 0;
let grantSignature = "";
let rowSignature = "";
let account = null;
const receipts = new Map();
let dialogCommit = null;
const modal = $("#modal");

async function api(path, data) {
  if (!access) throw new Error("请使用启动终端打印的申请人或审批员链接打开工作台。");
  const options = { method: data === undefined ? "GET" : "POST", headers: { Authorization: "Bearer " + access }, cache: "no-store", credentials: "omit" };
  if (data !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(data);
  }
  const response = await fetch("/api/" + path, options);
  const type = response.headers.get("content-type") || "";
  const body = type.includes("application/json") ? await response.json() : {};
  if (!response.ok) {
    const err = new Error(typeof body.error === "string" ? body.error : "操作失败（HTTP " + response.status + "）");
    err.status = response.status;
    throw err;
  }
  return body;
}

function message(content, error = false) {
  const box = $("#message");
  box.hidden = !content;
  box.textContent = content;
  box.classList.toggle("error", error);
}
function connection(ok, text) {
  $("#connection-dot").classList.toggle("online", ok);
  $("#sync-state").textContent = text;
}
function badge(text, flavor) { return node("span", text, "pill " + (flavor || "")); }
function grantButton(title, method, grant, primary = false) {
  const button = node("button", title, "button minor " + (primary ? "primary" : "secondary"));
  button.type = "button";
  button.dataset.action = method;
  button.dataset.id = grant.id;
  button.disabled = busy;
  return button;
}
function capability(env, kind) { return state?.capabilities?.[env]?.[kind]; }
function requestOptions() {
  const available = state?.capabilities?.[state?.environment] || {};
  return Object.entries(available).filter(([kind]) => kind === "diagnose" || kind === "retry");
}
function labelFor(kind) {
  if (state?.mode === "external") return {diagnose: "限时授权", retry:"单次授权"}[kind] || kind;
  return grantNames[kind] || kind;
}
function routeText(env, kind) {
  const route = capability(env,kind);
  return route && state?.mode === "external" ? route.method + " " + route.origin + route.path : "";
}
let environmentSignature = "";
function renderEnvironments() {
  const names = [...(state?.environments || [])].sort((a,b) => {
    const order = ["DEV","STG","PROD"];
    const rank = n => order.includes(n) ? order.indexOf(n) : 3;
    return rank(a) - rank(b) || a.localeCompare(b);
  });
  const sig = JSON.stringify(names);
  if (sig === environmentSignature) return;
  environmentSignature = sig;
  const cards = names.map(name => {
    const b=node("button",undefined,"env-card"); b.type="button"; b.dataset.env=name;
    const mark=node("span",undefined,"env-mark "+({DEV:"dev",STG:"stg",PROD:"prod"}[name] || "dev"));
    const indicator=node("span",undefined,"env-indicator"); indicator.setAttribute("aria-hidden","true");
    b.append(mark,node("strong",name),node("span",envNames[name] || "服务环境"),indicator); return b;
  });
  $("#env-grid").replaceChildren(...cards);
  const envFilter=$("#event-env"), previous=envFilter.value;
  envFilter.replaceChildren(new Option("全部环境",""),...names.map(name=>new Option(name,name)));
  if (names.includes(previous)) envFilter.value=previous;
}
function renderGrants() {
  const grants = state?.grants || [];
  const signature = JSON.stringify([state?.role, state?.environment, grants, busy, [...receipts]]);
  if (signature === grantSignature) return;
  grantSignature = signature;
  $("#grant-count").textContent = grants.length;
  const items = [];
  for (const g of grants) {
    const item = node("article", undefined, "grant");
    const left = node("div");
    const title = node("div", undefined, "grant-title");
    title.append(node("h3", labelFor(g.action)), badge(statusNames[g.status] || g.status, { pending:"wait", approved:"good", denied:"bad" }[g.status]));
    const desc = node("small", [g.environment, g.resource, routeText(g.environment,g.action), "截至 " + formatTime(g.expires_at)].filter(Boolean).join(" · "));
    left.append(title, desc);
    if (receipts.has(g.id)) left.append(node("span", receipts.get(g.id), "receipt"));
    item.append(left);
    const actions = node("div", undefined, "grant-buttons");
    if (g.status === "pending" && state.role === "owner") actions.append(grantButton("审阅批准", "approve", g, true), grantButton("拒绝", "deny", g));
    if (g.status === "approved" && state.role === "alice" && g.environment === state.environment) actions.append(grantButton("执行", "use", g, true));
    if (state.supports_outcome && g.status === "consumed" && g.action === "retry") actions.append(grantButton("查看回执", "outcome", g));
    if (g.status === "approved" || (g.status === "pending" && state.role === "alice")) actions.append(grantButton("收回", "revoke", g));
    item.append(actions);
    items.push(item);
  }
  if (!items.length) {
    const empty = !state ? "尚未获取授权状态。" : state.role === "owner" ? "暂无授权申请。申请人提交后会显示在这里。" :
      requestOptions().length ? "暂无授权申请。可申请本环境已配置的临时权限。" : "当前环境没有临时权限申请。";
    items.push(node("p", empty, "empty"));
  }
  const focused = document.activeElement?.closest("#grants [data-action]");
  const hadFocus = !!focused && !modal.open;
  $("#grants").replaceChildren(...items);
  if (hadFocus) {
    const replacement = [...$("#grants").querySelectorAll("[data-action]")].find(button =>
      button.dataset.id === focused.dataset.id && button.dataset.action === focused.dataset.action && !button.disabled);
    if (replacement) replacement.focus({preventScroll: true});
    else if (!busy) $("#grant-heading").focus({preventScroll: true});
  }
}
function renderState() {
  const who = state?.role;
  const current = state?.environment;
  renderEnvironments();
  $("#task-name").textContent=state?.task || "—";
  $("#account-label").textContent=state?.mode==="external" ? "最近使用的凭据引用" : "最近响应账户";
  $("#role-name").textContent = state?.actor || who || "未连接";
  $("#role-caption").textContent = who === "owner" ? "审批员" : who === "alice" ? "任务申请人" : "当前身份";
  $("#env-context").textContent = current ? "当前会话 · " + current : "尚未选择环境";
  $("#base-status").textContent = current ? "只读" : "尚未建立";
  $("#last-account").textContent = account?.environment === current && account?.name ? account.name : "—";
  $("#read").hidden = who === "owner";
  $("#read").disabled = busy || !current || who !== "alice";
  $("#end").hidden = who !== "alice" || !current;
  $("#end").disabled = busy;
  $("#request").hidden = who === "owner";
  $("#request").disabled = busy || !requestOptions().length || who !== "alice";
  for (const button of document.querySelectorAll("[data-env]")) {
    const selected = button.dataset.env === current;
    button.classList.toggle("chosen", selected);
    button.setAttribute("aria-pressed", String(selected));
    button.setAttribute("aria-label", button.dataset.env + " " + (envNames[button.dataset.env] || "服务环境") + (selected ? "，当前环境" : ""));
    button.disabled = busy || who !== "alice" || selected;
  }
  renderGrants();
}
function eventDetail(ev, expanded) {
  const raw = String(ev.detail || "—");
  const summary = raw
    .replace(/有效至 (\d{13})\b/g, (_, ms) => "有效至 " + formatTime(ms))
    .replace(/\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b/gi,
      id => "#" + id.slice(0, 8) + "…" + id.slice(-4))
    .replace(/动作 (diagnose|retry)\b/g, (_, key) => "动作 " + labelFor(key));
  const cell = node("td");
  if (summary === raw) {
    cell.textContent = raw;
    return cell;
  }
  const details = node("details", undefined, "event-detail");
  details.dataset.event = String(ev.id);
  details.open = expanded.has(String(ev.id));
  const head = node("summary", summary);
  head.title = "展开或收起完整记录";
  details.append(head, node("span", "原始记录", "detail-label"), node("code", raw, "detail-raw"));
  cell.append(details);
  return cell;
}
function renderRows() {
  const signature = JSON.stringify(rows);
  if (signature !== rowSignature) {
    rowSignature = signature;
    const expanded = new Set([...$("#events").querySelectorAll("details[open]")].map(d => d.dataset.event));
    const focusID = document.activeElement?.closest("#events details")?.dataset.event;
    const body = document.createDocumentFragment();
    for (const ev of rows) {
      const tr = node("tr");
      tr.append(node("td", formatTime(ev.at), "event-time mono"));
      const operation = node("td");
      const admission = ev.action === "admit" || (ev.action === "use" && (ev.detail || "").startsWith("已受理单次操作"));
      const upstreamCall = ["use","read","sdk_read"].includes(ev.action);
      operation.append(node("b", admission ? "受理单次操作" : (events[ev.action] || ev.action)), node("span", ev.resource || "—", "event-resource"));
      tr.append(operation, node("td", ev.environment || "—", "event-env mono"), node("td", ev.actor || "—", "mono"));
      const result = node("td");
      const resultText = admission ? "待回执" : (upstreamCall && ev.result === "allowed" ? (state?.mode === "external" ? "上游响应" : "上游成功") : resultNames[ev.result] || ev.result);
      result.append(badge(resultText, admission ? "wait" : ev.result === "allowed" ? "good" : "bad"));
      tr.append(result, eventDetail(ev, expanded));
      body.append(tr);
    }
    if (!rows.length) {
      const tr = node("tr");
      const td = node("td", "暂无操作记录", "empty-cell");
      td.colSpan = 6;
      tr.append(td);
      body.append(tr);
    }
    $("#events").replaceChildren(body);
    if (focusID) {
      const match = [...$("#events").querySelectorAll("details")].find(d => d.dataset.event === focusID);
      match?.querySelector("summary").focus({preventScroll: true});
    }
  }
  $("#event-count").textContent = "已显示 " + rows.length + " 条记录";
  $("#more").hidden = !hasOlder;
  $("#more").disabled = paging || busy;
}
function queryEvents(before) {
  const q = new URLSearchParams({limit: String(pageSize)});
  if ($("#event-env").value) q.set("environment", $("#event-env").value);
  if (before !== undefined) q.set("before", before);
  return api("events?" + q);
}
async function refresh(quiet = false) {
  const turn = ++liveRevision;
  const revision = eventRevision;
  if (!quiet) $("#refresh").disabled = true;
  try {
    const [snapshot, history] = await Promise.all([api("state"), queryEvents()]);
    if (turn !== liveRevision) return;
    if (snapshot.role !== "alice" && snapshot.role !== "owner") throw new Error("无法识别当前身份。");
    if (state && state.environment !== snapshot.environment) account = null;
    state = snapshot;
    const visibleGrants = new Set((snapshot.grants || []).map(grant => grant.id));
    for (const id of receipts.keys()) if (!visibleGrants.has(id)) receipts.delete(id);
    renderState();
    if (eventRevision === revision && !paging) {
      const fresh = history.events || [];
      // Keep already loaded older pages only when the new page overlaps them.
      const previous = new Map(rows.map(ev => [ev.id, ev]));
      const overlap = fresh.some(ev => previous.has(ev.id));
      const keepPages = overlap && rows.length && rows.at(-1).id < fresh.at(-1).id;
      rows = keepPages ? [...fresh, ...rows.filter(ev => ev.id < fresh.at(-1).id)] : fresh;
      if (!keepPages) hasOlder = fresh.length === pageSize;
      renderRows();
    }
    connection(true, "已连接");
    if (!quiet && $("#message").classList.contains("error")) message("");
  } catch (err) {
    if (turn !== liveRevision) return;
    connection(false, "连接异常");
    if (err.status === 401) {
      state = null; rows = []; hasOlder = false; account = null; receipts.clear();
    }
    message(err.status === 401 ? "当前身份链接已失效，请重新打开启动终端中的链接。" : err.message, true);
    if (!state) { renderState(); renderRows(); }
  } finally {
    if (turn === liveRevision) $("#refresh").disabled = busy;
  }
}
async function loadMore() {
  if (paging || !rows.length) return;
  paging = true;
  const revision = ++eventRevision;
  const before = rows.at(-1).id;
  renderRows();
  try {
    const history = await queryEvents(before);
    if (eventRevision !== revision) return;
    const batch = history.events || [];
    const seen = new Set(rows.map(ev => ev.id));
    rows = rows.concat(batch.filter(ev => !seen.has(ev.id)));
    hasOlder = batch.length === pageSize;
  } catch (err) {
    if (eventRevision === revision) message(err.message, true);
  } finally {
    if (revision === eventRevision) { paging = false; renderRows(); }
  }
}

function openDialog(title, content, submit, callback, danger = false) {
  $("#dialog-title").textContent = title;
  $("#dialog-body").replaceChildren(...content);
  $("#submit").textContent = submit;
  $("#submit").className = "button " + (danger ? "danger" : "primary");
  dialogCommit = callback;
  modal.showModal();
  $("#cancel").focus();
}
$("#cancel").addEventListener("click", () => modal.close());
modal.addEventListener("close", () => { dialogCommit = null; });
$("#modal-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const action = dialogCommit;
  modal.close();
  if (action) action();
});
async function mutate(method, data, success) {
  if (busy) return;
  busy = true;
  liveRevision++;
  $("#refresh").disabled = true;
  renderState();
  let note;
  let failed = false;
  try {
    const response = await api(method, data);
    if (response.account) account = { name: response.account, environment: response.environment };
    if (method === "switch" || method === "end") { account = null; receipts.clear(); }
    note = response.account ? (state?.mode === "external" ? "上游响应 HTTP " + response.upstream_status + " · 凭据引用 " + response.account : success + " · 上游账户 " + response.account) : success;
    if (method === "outcome") {
      const stateText = {applied:"已执行（applied）", unconfirmed:"尚未确认（unconfirmed）"}[response.state];
      if (!stateText) throw new Error("上游返回了未知的回执状态。");
      note = "上游回执 · " + stateText;
      if (Number.isInteger(response.run_number)) note += " · 执行序号 " + response.run_number;
      receipts.set(data.id, note);
    }
  } catch (err) {
    note = err.message;
    failed = true;
  } finally {
    await refresh(true);
    busy = false;
    renderState();
    renderRows();
    $("#refresh").disabled = false;
    if (!$("#connection-dot").classList.contains("online")) note += "。当前数据尚未刷新。";
    message(note, failed);
  }
}
$("#env-grid").addEventListener("click", event => {
  const button=event.target.closest("[data-env]");
  if (!button || button.disabled) return;
  const target = button.dataset.env;
  const run = () => mutate("switch", {environment: target}, "已建立 " + target + " 会话");
  if (!state?.environment) { run(); return; }
  openDialog("切换到 " + target + "？", [node("p", "切换会收回当前 " + state.environment + " 会话及临时授权。")], "确认切换", run);
});
$("#read").addEventListener("click", () => mutate("read", {}, "服务读取成功"));
$("#end").addEventListener("click", () => {
  if (state?.role !== "alice" || !state.environment) return;
  openDialog("结束 " + state.environment + " 会话？",
    [node("p", "结束后会收回基础访问和该任务的临时授权，已保存的操作记录仍可查看。")],
    "确认结束", () => mutate("end", {}, "会话已结束"), true);
});
$("#request").addEventListener("click", () => {
  const action = node("select"); action.id = "request-action";
  const options=requestOptions();
  if (!options.length) return;
  for (const [value, rule] of options) {
    action.append(new Option(labelFor(value) + " · " + rule.resource, value));
  }
  const ttl = node("input"); ttl.type = "number"; ttl.id = "request-ttl"; ttl.min = "1"; ttl.max = "900"; ttl.value = "60"; ttl.required = true;
  const scope=node("p");
  const adjust=() => {
    const rule=capability(state.environment,action.value);
    ttl.max=String(rule.max_ttl); ttl.value=String(Math.min(Number(ttl.value) || 60,rule.max_ttl));
    scope.textContent=routeText(state.environment,action.value);
  };
  action.addEventListener("change", adjust); adjust();
  const field1 = node("label", "申请操作"); field1.append(action);
  const field2 = node("label", "有效时长（秒）"); field2.append(ttl);
  openDialog("申请 " + state.environment + " 临时权限", [field1, field2, ...(scope.textContent ? [scope]:[])], "提交申请",
    () => mutate("request", {action: action.value, ttl: Number(ttl.value)}, "申请已提交，等待审批"));
  action.focus();
});
$("#grants").addEventListener("click", event => {
  const button = event.target.closest("[data-action]");
  if (!button || busy) return;
  const method = button.dataset.action;
  const g = state.grants.find(grant => String(grant.id) === button.dataset.id);
  if (!g) return;
  if (method === "outcome") {
    mutate("outcome", {id:g.id}, "已查询上游回执");
    return;
  }
  const labels = {approve:["批准这项申请？","确认批准","申请已批准"],deny:["拒绝这项申请？","确认拒绝","申请已拒绝"],use:["执行授权操作？","确认执行","操作已执行"],revoke:["收回这项权限？","确认收回","授权已收回"]};
  const [title, submit, success] = labels[method];
  const run = () => mutate(method, {id:g.id}, success);
  if (method === "use" && g.action === "diagnose") { run(); return; }
  openDialog(title, [node("p", g.environment + " · " + (labelFor(g.action)) + " · " + g.resource), ...(routeText(g.environment,g.action)?[node("p",routeText(g.environment,g.action))]:[]), node("p", "有效期至 " + formatTime(g.expires_at))],
    submit, run, method === "deny" || method === "revoke");
});
$("#event-env").addEventListener("change", () => {
  eventRevision++;
  rows = []; hasOlder = false; paging = false;
  renderRows();
  refresh();
});
$("#refresh").addEventListener("click", () => refresh());
$("#more").addEventListener("click", loadMore);
for (const link of document.querySelectorAll(".nav-item")) {
  link.addEventListener("click", () => {
    for (const item of document.querySelectorAll(".nav-item")) item.classList.toggle("current", item === link);
  });
}
function poll() {
  if (!document.hidden && !busy && !modal.open && !paging && access) refresh(true);
}
document.addEventListener("visibilitychange", poll);
window.setInterval(poll, 6000);
refresh();
