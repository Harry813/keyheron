"""Trusted, single-process policy controller for the local Agent access demo.

The runner supplies an already authenticated actor. These methods are not an
authentication endpoint and must never take the actor from an untrusted request.
"""
import math
import secrets
import threading
import time
from dataclasses import dataclass, field


class Denied(PermissionError):
    """The trusted controller refused this operation."""


READ_ENVIRONMENTS = {"alice": {"DEV", "STG", "PROD"}, "bob": {"DEV"}}
APPROVERS = {"owner"}
REQUESTERS = {"alice"}
BASE_TTL = 900
# The requesting agent never supplies a URL, HTTP method, or credential name.
OPERATIONS = {
    ("diagnose", "orders"): ("GET", "/service/diagnostics"),
    ("retry", "job-4821"): ("POST", "/jobs/job-4821/retry"),
}


@dataclass
class Task:
    owner: str
    environment: str | None = None
    base_token: str | None = field(default=None, repr=False)
    deadline: float = 0
    active: bool = False
    grants: set[str] = field(default_factory=set)


@dataclass
class Grant:
    actor: str
    task: str
    environment: str
    action: str
    resource: str
    deadline: float
    state: str = "pending"
    token: str | None = field(default=None, repr=False)


class Access:
    def __init__(self, rt, *, clock=time.monotonic):
        self._runtime = rt
        self._clock = clock
        self._tasks: dict[str, Task] = {}
        self._grants: dict[str, Grant] = {}
        self._lock = threading.Lock()

    def start_task(self, actor: str, task: str) -> None:
        with self._lock:
            if actor not in READ_ENVIRONMENTS or not task or task in self._tasks:
                raise Denied("无权创建任务，或任务编号已被使用")
            self._tasks[task] = Task(actor)

    def _owned_task(self, actor, task_id):
        task = self._tasks.get(task_id)
        if task is None or task.owner != actor:
            raise Denied("无权操作此任务")
        return task

    def _grant(self, request_id):
        grant = self._grants.get(request_id)
        if grant is None:
            raise Denied("授权申请不存在或已经失效")
        return grant

    def _require_current(self, grant):
        task = self._owned_task(grant.actor, grant.task)
        if not task.active or grant.environment != task.environment:
            raise Denied("申请不属于当前活动环境")
        if self._clock() >= min(task.deadline, grant.deadline):
            raise Denied("任务会话或临时授权已经过期")

    def _revoke_grant(self, grant):
        grant.state = "revoked"
        if grant.token is not None:
            self._runtime[grant.environment].revoke(grant.token)
            grant.token = None

    def _close_environment(self, task):
        # Stop granting access immediately. Keep unconfirmed broker handles so
        # the host can retry cleanup; never report a successful switch early.
        task.active = False
        failures = []
        if task.base_token is not None:
            try:
                self._runtime[task.environment].revoke(task.base_token)
                task.base_token = None
            except Exception as exc:
                failures.append(exc)
        for request_id in list(task.grants):
            try:
                self._revoke_grant(self._grants[request_id])
                del self._grants[request_id]
                task.grants.remove(request_id)
            except Exception as exc:
                failures.append(exc)
        if failures:
            raise RuntimeError("代理尚未确认全部撤销；请重试清理，不能启用新环境") from failures[0]
        task.environment = None

    def switch(self, actor: str, task: str, env: str) -> str:
        with self._lock:
            current = self._owned_task(actor, task)
            if env not in READ_ENVIRONMENTS[actor]:
                raise Denied("当前身份没有目标环境的读取权限")
            self._close_environment(current)
            deadline = self._clock() + BASE_TTL
            token = self._runtime[env].issue("read", BASE_TTL, task_id=task, actor=actor)
            current.environment = env
            current.base_token = token
            current.deadline = deadline
            current.active = True
            return token

    def request(self, actor: str, task: str, action: str, resource: str, ttl: int = 60) -> str:
        with self._lock:
            current = self._owned_task(actor, task)
            now = self._clock()
            if not current.active or current.deadline <= now:
                raise Denied("需要有效的基础会话")
            if actor not in REQUESTERS or current.environment != "PROD" or (action, resource) not in OPERATIONS:
                raise Denied("当前身份、环境或资源不允许申请这项操作")
            if type(ttl) is not int or not 1 <= ttl <= BASE_TTL:
                raise Denied("授权时限必须为 1 到 900 秒的整数")
            request_id = secrets.token_hex(16)
            self._grants[request_id] = Grant(actor, task, current.environment, action, resource,
                                              min(current.deadline, now + ttl))
            current.grants.add(request_id)
            return request_id

    def status(self, actor: str, task: str) -> dict:
        with self._lock:
            current = self._owned_task(actor, task)
            now = self._clock()
            active = current.active and current.deadline > now
            temporary = []
            if active:
                for request_id in sorted(current.grants):
                    grant = self._grants[request_id]
                    if grant.state == "approved" and grant.deadline > now:
                        temporary.append({"action": grant.action, "resource": grant.resource,
                                          "seconds_left": math.ceil(grant.deadline - now)})
            return {"environment": current.environment if active else None,
                    "base": ["read"] if active else [], "temporary": temporary}

    def review(self, approver: str, request_id: str) -> dict:
        with self._lock:
            grant = self._grant(request_id)
            self._require_approver(approver, grant)
            return {"actor": grant.actor, "task": grant.task, "environment": grant.environment,
                    "action": grant.action, "resource": grant.resource,
                    "seconds_left": math.ceil(grant.deadline - self._clock())}

    def _require_approver(self, approver, grant):
        if approver not in APPROVERS or approver == grant.actor:
            raise Denied("需由独立审批人批准")
        self._require_current(grant)
        if grant.state != "pending":
            raise Denied("申请已处理")

    def approve(self, approver: str, request_id: str) -> None:
        with self._lock:
            grant = self._grant(request_id)
            self._require_approver(approver, grant)
            remaining = math.ceil(grant.deadline - self._clock())
            if remaining <= 0:
                raise Denied("申请已过期")
            grant.token = self._runtime[grant.environment].issue(
                grant.action, remaining, task_id=grant.task, actor=grant.actor)
            grant.state = "approved"

    def use(self, actor: str, request_id: str) -> tuple[int, dict]:
        # Serialise forwarding with switch/revoke, and consume a one-shot
        # grant before sending its request. A timeout never triggers a retry.
        with self._lock:
            grant = self._grant(request_id)
            if actor != grant.actor or grant.state != "approved":
                raise Denied("授权未批准、已使用或已收回")
            self._require_current(grant)
            broker = self._runtime[grant.environment]
            method, path = OPERATIONS[grant.action, grant.resource]
            if grant.action == "diagnose":
                return broker.call(grant.token, method, path)
            grant.state = "consumed"
            try:
                return broker.call(grant.token, method, path, operation_id=request_id)
            finally:
                broker.revoke(grant.token)
                grant.token = None

    def revoke(self, actor: str, request_id: str) -> None:
        with self._lock:
            grant = self._grant(request_id)
            if actor != grant.actor and actor not in APPROVERS:
                raise Denied("无权收回此授权")
            self._revoke_grant(grant)

    def outcome(self, actor: str, request_id: str) -> dict:
        with self._lock:
            grant = self._grant(request_id)
            if actor != grant.actor and actor not in APPROVERS:
                raise Denied("无权查询该回执")
            if grant.action != "retry" or grant.state != "consumed":
                raise Denied("没有已提交的单次操作")
            return self._runtime[grant.environment].operation_result(request_id)

    def end(self, actor: str, task: str) -> None:
        with self._lock:
            current = self._owned_task(actor, task)
            self._close_environment(current)
            del self._tasks[task]
