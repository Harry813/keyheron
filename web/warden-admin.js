"use strict";

const byId = id => document.getElementById(id);
const token = new URLSearchParams(location.hash.slice(1)).get("access");
history.replaceState(null, "", location.pathname);
let state;
let busy = false;
let nextRule = 0;

function message(value, error = false) {
  byId("message").textContent = value;
  byId("message").classList.toggle("error", error);
}

async function api(path, payload) {
  const headers = {Authorization: "Bearer " + token};
  const options = {headers, credentials: "omit", cache: "no-store", redirect: "error"};
  if (payload) {
    headers["Content-Type"] = "application/json";
    options.method = "POST";
    options.body = JSON.stringify(payload);
  }
  const response = await fetch("/api/" + path, options);
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "管理请求失败");
  return body;
}

function item(parent, text) {
  const child = document.createElement("li");
  child.textContent = text;
  parent.append(child);
  return child;
}

function options(id, names) {
  const select = byId(id);
  const previous = select.value;
  select.replaceChildren(...names.map(name => new Option(name, name)));
  if (names.includes(previous)) select.value = previous;
}

function buttons() {
  byId("refresh").disabled = busy || !token;
  byId("save-template").disabled = busy || !state;
  byId("apply-template").disabled = busy || !state || !byId("warden").value || !byId("binding-template").value;
  for (const button of document.querySelectorAll("#bindings button")) button.disabled = busy || !state;
}

const actionLabels = new Map([
  ["gitlab/read", "GitLab · 读取"],
  ["postgresql/connect", "PostgreSQL · 连接"],
  ["mysql/connect", "MySQL · 连接"],
  ["sqlserver/connect", "SQL Server · 连接"],
  ["database/connect", "数据库（旧授权）· 连接"],
]);

function actionLabel(connector, action) {
  return actionLabels.get(connector + "/" + action) || [connector, action].filter(Boolean).join(" · ") || "—";
}

function showActions(select) {
  const previous = select.value;
  const actions = state?.actions || {};
  select.replaceChildren(...Object.entries(actions).map(([connector, action]) =>
    new Option(actionLabel(connector, action), connector)));
  if (Object.hasOwn(actions, previous)) select.value = previous;
}

function render() {
  const {templates = {}, wardens} = state.policy;
  document.querySelectorAll("#rules [data-field=connector]").forEach(showActions);
  const list = byId("templates");
  list.replaceChildren();
  for (const [name, rules] of Object.entries(templates)) {
    const details = document.createElement("details");
    const heading = document.createElement("summary");
    heading.textContent = name + " · " + rules.length + " 条规则";
    const children = document.createElement("ul");
    rules.forEach(rule => item(children, [actionLabel(rule.connector, rule.action), rule.resource, rule.ttl + " 秒"].join(" / ")));
    details.append(heading, children);
    item(list, "").append(details);
  }
  if (!list.children.length) item(list, "尚无基础模板");
  options("warden", Object.keys(wardens));
  options("binding-template", Object.keys(templates));
  const bindings = byId("bindings");
  bindings.replaceChildren();
  for (const [warden, entry] of Object.entries(wardens)) {
    for (const [task, grant] of Object.entries(entry.tasks)) {
      const name = Array.isArray(grant) ? "直接规则（" + grant.length + " 条）" : grant.template;
      const row = item(bindings, warden + " / " + task + " · " + name);
      const revoke = document.createElement("button");
      revoke.type = "button";
      revoke.className = "button secondary minor";
      revoke.textContent = "撤销";
      revoke.setAttribute("aria-label", "撤销 " + warden + " 的任务 " + task + " 授权");
      revoke.addEventListener("click", () => {
        if (window.confirm("撤销 " + warden + " 的任务 " + task + " 的所有连接器授权？")) {
          update("revoke", {warden, task}, "已撤销任务授权。", () => byId("task").focus());
        }
      });
      row.append(revoke);
    }
  }
  if (!bindings.children.length) item(bindings, "尚无任务授权");
  buttons();
}

async function audit() {
  const body = byId("events");
  let data;
  try {
    data = await api("events");
  } catch {
    data = {message: "无法读取审计库，请核对控制服务和文件路径。", events: []};
  }
  body.replaceChildren();
  if (!data.events.length) {
    const cell = body.insertRow().insertCell();
    cell.colSpan = 6;
    cell.textContent = data.message || (data.ready ? "尚无审计事件" : "控制服务尚未创建此审计库");
    return;
  }
  for (const event of data.events) {
    const row = body.insertRow();
    for (const value of [event.at, event.warden + " / " + event.task,
      actionLabel(event.connector, event.action), event.resource || "—", event.kind, event.result]) {
      row.insertCell().textContent = value;
    }
  }
}

async function refresh() {
  if (!token || busy) return;
  const trigger = document.activeElement;
  busy = true;
  buttons();
  try {
    state = await api("state");
    render();
    await audit();
    message("已读取最新策略和审计状态。");
  } catch (error) {
    state = null;
    message(error.message, true);
  } finally {
    busy = false;
    buttons();
    if (document.activeElement === document.body && trigger.isConnected) trigger.focus();
  }
}

async function update(operation, payload, success, after) {
  if (busy || !state) return;
  const trigger = document.activeElement;
  busy = true;
  buttons();
  let done = false;
  try {
    state = await api(operation, {revision: state.revision, ...payload});
    render();
    await audit();
    message(success);
    done = true;
  } catch (error) {
    message(error.message, true);
  } finally {
    busy = false;
    buttons();
  }
  if (done && after) after();
  else if (document.activeElement === document.body && trigger.isConnected) trigger.focus();
}

function addRule(focus = false) {
  const row = byId("rule-row").content.firstElementChild.cloneNode(true);
  const number = ++nextRule;
  row.querySelector("legend").textContent = "规则 " + number;
  for (const control of row.querySelectorAll("[data-field]")) {
    control.id = "rule-" + number + "-" + control.dataset.field;
    control.previousElementSibling.htmlFor = control.id;
  }
  showActions(row.querySelector("select"));
  row.querySelector("button").addEventListener("click", () => {
    row.remove();
    syncRules();
    byId("add-rule").focus();
  });
  byId("rules").append(row);
  syncRules();
  if (focus) row.querySelector("select").focus();
}

function syncRules() {
  const buttons = document.querySelectorAll("#rules button");
  for (const button of buttons) button.disabled = buttons.length === 1;
}

byId("refresh").addEventListener("click", refresh);
byId("add-rule").addEventListener("click", () => addRule(true));
byId("template-form").addEventListener("submit", event => {
  event.preventDefault();
  const name = byId("name").value;
  const rules = [...byId("rules").children].map(row => {
    const field = name => row.querySelector('[data-field="' + name + '"]').value;
    const connector = field("connector");
    return {connector, action: state.actions[connector], resource: field("resource"), ttl: Number(field("ttl"))};
  });
  update("template", {template: name, rules}, "已创建模板 " + name + "。", () => {
    byId("binding-template").value = name;
    byId("name").value = "";
    byId("rules").replaceChildren();
    addRule();
    byId("name").focus();
  });
});
byId("bind-form").addEventListener("submit", event => {
  event.preventDefault();
  const warden = byId("warden").value;
  const task = byId("task").value;
  const template = byId("binding-template").value;
  if (Object.hasOwn(state.policy.wardens[warden].tasks, task) &&
      !window.confirm("使用 " + template + " 替换任务 " + task + " 当前的权限？")) return;
  update("bind", {warden, task, template}, "已对任务 " + task + " 应用模板 " + template + "。");
});

addRule();
buttons();
if (token) refresh();
else message("请通过管理员终端中的私有本地入口重新打开此面板。", true);
