"""运行 Rust 交互控制台，或独立的 Python 参考回归（使用本地模拟账户）。"""
import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor

from access import Access, Denied
from runtime import DemoRuntime
from tools import keyfence_binary


def expect(condition, message):
    if not condition:
        raise RuntimeError("验收失败：" + message)


def refused(operation):
    try:
        operation()
    except Denied:
        return True
    return False


def account(response, expected):
    status, body = response
    expect(status == 200 and body.get("account") == expected, f"上游未确认 {expected}（HTTP {status}）")
    return body["account"]


def run(binary, emit):
    task = "orders-investigation"
    actor = "alice"
    approver = "owner"
    steps = []

    def record(title, **facts):
        entry = {"step": title, **facts}
        steps.append(entry)
        emit(entry)

    with DemoRuntime(binary) as rt:
        access = Access(rt)
        access.start_task(actor, task)
        access.start_task("bob", "dev-only")

        def read(env, token):
            return rt[env].call(token, "GET", "/service/status")

        dev = access.switch(actor, task, "DEV")
        record("DEV 基础读取", upstream=account(read("DEV", dev), "dev-reader"))
        stg = access.switch(actor, task, "STG")
        old_dev, cross_env = read("DEV", dev)[0], read("DEV", stg)[0]
        expect((old_dev, cross_env) == (403, 403), "旧会话或另一环境令牌能访问 DEV")
        record("切换 STG 并收回 DEV", upstream=account(read("STG", stg), "stg-reader"),
               old_dev=old_dev, stg_token_at_dev=cross_env)
        bob_dev = access.switch("bob", "dev-only", "DEV")
        expect(refused(lambda: access.switch("bob", "dev-only", "PROD")), "低权限主体可切换 PROD")
        expect(refused(lambda: access.switch("bob", task, "DEV")), "其他主体可切换本任务")
        record("Bob 申请 PROD 被拒，保留自己的 DEV 会话", upstream=account(read("DEV", bob_dev), "dev-reader"))

        prod = access.switch(actor, task, "PROD")
        before = rt["PROD"].call(prod, "GET", "/service/diagnostics")[0]
        expect(before == 403 and read("STG", stg)[0] == 403, "基础权限范围错误")
        record("PROD 默认只读", upstream=account(read("PROD", prod), "prod-reader"),
               diagnostics_before_approval=before)
        diag = access.request(actor, task, "diagnose", "orders", ttl=60)
        expect(refused(lambda: access.approve(actor, diag)), "允许自批")
        expect(refused(lambda: access.use(actor, diag)), "待审批期间仍可使用高权")
        approval = access.review(approver, diag)
        expect((approval["environment"], approval["action"], approval["resource"]) ==
               ("PROD", "diagnose", "orders"), "审批摘要与实际目标不一致")
        access.approve(approver, diag)
        expect(refused(lambda: access.use("bob", diag)), "跨主体借用已批准授权")
        record("独立审批后临时读取诊断", approved_by=approver, grant=approval,
               upstream=account(access.use(actor, diag), "prod-diagnostics"),
               current=access.status(actor, task))
        access.revoke(approver, diag)
        expect(refused(lambda: access.use(actor, diag)) and not access.status(actor, task)["temporary"],
               "撤销诊断后仍有高权")
        record("单独撤销诊断，基础读取继续", upstream=account(read("PROD", prod), "prod-reader"))

        expect(refused(lambda: access.request(actor, task, "retry", "job-out-of-scope")),
               "允许审批未注册的资源")
        retry = access.request(actor, task, "retry", "job-4821")
        access.approve(approver, retry)

        def use_once(_):
            try:
                return access.use(actor, retry)[0]
            except Denied:
                return "denied"

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(use_once, range(8)))
        effects = [row for row in rt["PROD"].observations if row.get("operation_id") == retry]
        expect(outcomes.count(200) == 1 and outcomes.count("denied") == 7, "单次审批未被原子消费")
        expect(len(effects) == 1 and effects[0]["account"] == "prod-worker"
               and effects[0]["executions"] == 1, "上游执行次数或主体错误")
        record("一次性重跑 job-4821，并发提交 8 次", accepted=1, refused=7,
               upstream=effects[0]["account"], upstream_operations=len(effects))

        timed = access.request(actor, task, "diagnose", "orders", ttl=2)
        access.approve(approver, timed)
        account(access.use(actor, timed), "prod-diagnostics")
        time.sleep(2.1)
        expect(refused(lambda: access.use(actor, timed)), "临时授权到期后仍可使用")
        record("临时权限自然到期", upstream=account(read("PROD", prod), "prod-reader"),
               current=access.status(actor, task))

        pending = access.request(actor, task, "retry", "job-4821")
        active = access.request(actor, task, "diagnose", "orders")
        access.approve(approver, active)
        dev2 = access.switch(actor, task, "DEV")
        expect(read("PROD", prod)[0] == 403 and refused(lambda: access.use(actor, active)),
               "切换后旧环境或高权限残留")
        prod2 = access.switch(actor, task, "PROD")
        expect(refused(lambda: access.approve(approver, pending)), "切回原环境后旧申请复活")
        expect(not access.status(actor, task)["temporary"] and read("DEV", dev2)[0] == 403,
               "切回时继承了临时授权")
        access.end(actor, task)
        access.end("bob", "dev-only")
        expect(read("PROD", prod2)[0] == 403 and read("DEV", bob_dev)[0] == 403,
               "结束任务后仍可读取")
        record("切换取消待审和已批授权，任务结束收回剩余会话", old_task_read=403)
    return {"result": "passed", "implementation": "python-reference", "broker": "KeyFence v0.4.0",
            "upstreams": "synthetic loopback HTTP",
            "identity": "trusted test fixtures", "steps": steps}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", help="使用已下载的官方 v0.4.0 可执行文件")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true", help="输出 Python 参考回归的验收记录")
    mode.add_argument("--interactive", action="store_true", help="同时启动网页和终端，共用 Rust 服务和 SQLite 记录")
    args = parser.parse_args()
    if args.interactive:
        from console import interactive
        try:
            interactive(keyfence_binary(args.binary))
        except (OSError, RuntimeError) as exc:
            parser.exit(1, f"交互控制台已停止。{exc}\n")
        return
    def show(step):
        if not args.json:
            details = {k: v for k, v in step.items() if k != "step"}
            print("✓", step["step"], json.dumps(details, ensure_ascii=False), flush=True)
    report = run(keyfence_binary(args.binary), show)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("Python 参考回归通过。三个临时代理和测试账户已回收。")


if __name__ == "__main__":
    main()
