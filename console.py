"""Trusted terminal client for the same loopback Rust API as the web console."""
from contextlib import closing
import http.client
import json
import math
from pathlib import Path
import sys
import time

from web_demo import ROOT, role_links, running


HELP = """命令
  env DEV|STG|PROD         切换环境并收回旧授权
  status                  查看环境、权限和当前申请编号
  read                    用基础权限读取服务状态
  request diagnose [秒]    申请限时诊断 orders（仅 PROD）
  request retry [秒]       申请单次重跑 job-4821（仅 PROD）
  review 编号              owner 核对待审内容，随后可批准或拒绝
  approve 编号 / reject 编号
  use 编号 / revoke 编号   使用或收回临时授权
  result 编号              核对已提交的单次操作回执
  help / exit"""


def _api(port, token, endpoint, body=None):
    headers = {"Authorization": "Bearer " + token}
    if body is not None:
        headers["Content-Type"] = "application/json"
    with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=15)) as conn:
        conn.request("GET" if body is None else "POST", "/api/" + endpoint,
                     body=None if body is None else json.dumps(body), headers=headers)
        response = conn.getresponse()
        data = json.loads(response.read())
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status} · {data.get('error', '操作失败')}")
        return data


def _print_account(data):
    result = f"HTTP 200 · {data['environment']} · 上游账户 {data['account']}"
    if "run_number" in data:
        result += f" · 本次任务执行序号 {data['run_number']}"
    print(result)


def interactive_client(port: int, tokens: dict) -> None:
    """Operate a running core; EOF and exit close the shared task in that core."""
    def alice(endpoint, body=None):
        return _api(port, tokens["alice"], endpoint, body)

    def owner(endpoint, body=None):
        return _api(port, tokens["owner"], endpoint, body)

    numbers = {}  # Terminal numbers stay stable even when the web UI creates other grants.
    def number_for(request_id):
        return numbers.setdefault(request_id, str(len(numbers) + 1))

    def current_grants(state):
        return {number_for(grant["id"]): grant for grant in state["grants"]}

    def seconds_left(grant):
        return max(0, math.ceil(grant["expires_at"] / 1000 - time.time()))

    print("本地可信演示终端。alice 申请，owner 审批，两种身份均由操作员模拟。终端与网页共用同一会话和记录。")
    last_reviewed = None
    try:
        initial = alice("state")
        environment = initial["environment"] or alice("switch", {"environment": "DEV"})["environment"]
        print(f"当前环境 {environment}，可输入 read 或 status。")
        print(HELP)
        while True:
            try:
                line = input("demo> " if sys.stdin.isatty() else "")
            except (EOFError, KeyboardInterrupt):
                break
            previous_review, last_reviewed = last_reviewed, None
            parts = line.split()
            if not parts:
                continue
            command, *args = parts
            try:
                if command == "exit" and not args:
                    break
                if command == "help" and not args:
                    print(HELP)
                elif command == "env" and len(args) == 1:
                    env = alice("switch", {"environment": args[0].upper()})["environment"]
                    print(f"{env} 新会话已建立。旧环境的授权已收回。")
                elif command == "status" and not args:
                    state = alice("state")
                    print(f"环境 {state['environment'] or '无活动会话'}，"
                          f"基础权限 {'read' if state['environment'] else '无'}。")
                    rows = current_grants(state)
                    if not rows:
                        print("当前无临时授权申请。")
                    for number, grant in sorted(rows.items(), key=lambda pair: int(pair[0])):
                        print(f"申请 {number} · {grant['environment']} · {grant['action']} {grant['resource']} · "
                              f"{grant['status']} · 剩余 {seconds_left(grant)} 秒")
                elif command == "read" and not args:
                    _print_account(alice("read", {}))
                elif command == "request" and len(args) in (1, 2) and args[0] in {"diagnose", "retry"}:
                    try:
                        ttl = int(args[1]) if len(args) == 2 else 60
                    except ValueError:
                        print("时限请填写整数秒。")
                        continue
                    grant = alice("request", {"action": args[0], "ttl": ttl})
                    number = number_for(grant["id"])
                    print(f"申请 {number} 待审。输入 review {number} 查看授权范围。")
                elif command in {"review", "approve", "reject", "use", "revoke", "result"} and len(args) == 1:
                    number = args[0]
                    state = (owner if command in {"review", "approve", "reject"} else alice)("state")
                    grant = current_grants(state).get(number)
                    if not grant:
                        print("当前会话中找不到该编号。输入 status 查看现有申请。")
                        continue
                    ref = {"id": grant["id"]}
                    if command == "review":
                        if grant["status"] != "pending" or grant["environment"] != state["environment"]:
                            print("该申请当前不可审批。")
                            continue
                        print(f"owner 审阅申请 {number}。alice / {state['task']} / {grant['environment']} / "
                              f"{grant['action']} / {grant['resource']}，剩余 {seconds_left(grant)} 秒。")
                        print(f"确认批准请接着输入 approve {number}，拒绝请输入 reject {number}。")
                        last_reviewed = grant["id"]
                    elif command in {"approve", "reject"}:
                        if previous_review != grant["id"]:
                            print(f"请先用 review {number} 核对申请，然后明确输入决定。")
                            continue
                        owner("approve" if command == "approve" else "deny", ref)
                        print(f"owner 已{'批准' if command == 'approve' else '拒绝'}申请 {number}。")
                    elif command == "use":
                        _print_account(alice("use", ref))
                    elif command == "result":
                        outcome = alice("outcome", ref)
                        run = outcome.get("run_number")
                        print(f"上游回执 {outcome['state']}" + (f"，执行序号 {run}。" if run else "。"))
                    else:
                        alice("revoke", ref)
                        print(f"已收回申请 {number} 的权限。")
                else:
                    print("命令或参数有误。输入 help 查看用法。")
            except RuntimeError as exc:
                print(exc)
            except (OSError, http.client.HTTPException, json.JSONDecodeError):
                print("未取得控制服务的有效响应，请核对操作记录和上游回执。")
    finally:
        alice("end", {})
    print("会话已结束，操作记录已保留。")


def interactive(binary: Path) -> None:
    db = ROOT / "data" / "events.sqlite3"
    with (running(binary, db) as (_, port, tokens),
          role_links(port, tokens["alice"], tokens["owner"])):
        print("两个角色链接在本次运行有效，请分开打开。")
        interactive_client(port, tokens)
