"""Expose this sandbox's Warden connector grants over MCP stdio (Python 3.11+)."""

import argparse
import asyncio
import os
from pathlib import Path


_TOOLS = {
    "list_connectors": ("列出当前 Warden 任务可用的连接器、操作和资源。", ()),
    "describe_connector": ("查看一个已授权连接器的操作和资源。", ("connector",)),
    "invoke_connector": (
        "在指定资源上调用已授权操作。数据库连接返回当前沙箱内的私有连接文件路径、句柄和到期时间。",
        ("connector", "action", "resource"),
    ),
    "close_connection": ("关闭本 MCP 会话打开的数据库连接。", ("handle",)),
}


def _input_schema(fields):
    properties = {}
    for field in fields:
        schema = {"type": "string", "minLength": 1, "maxLength": 128}
        if field != "handle":
            schema["pattern"] = "^[A-Za-z0-9][A-Za-z0-9_.:-]*$"
        properties[field] = schema
    return {"type": "object", "properties": properties, "required": list(fields), "additionalProperties": False}


async def _run(socket_path):
    try:
        from mcp import types
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
    except ImportError:
        raise RuntimeError("请安装可选依赖：python3 -m pip install -r requirements-mcp.txt") from None

    from warden_client import ConnectorSession

    server = Server("KeyHeron")
    async with stdio_server() as (reader, writer), ConnectorSession(socket_path) as session:
        @server.list_tools()
        async def list_tools():
            return [types.Tool(name=name, description=description, inputSchema=_input_schema(fields))
                    for name, (description, fields) in _TOOLS.items()]

        @server.call_tool(validate_input=True)
        async def call_tool(name, arguments):
            try:
                if name == "list_connectors":
                    return {"connectors": await session.list()}
                if name == "describe_connector":
                    return await session.describe(arguments["connector"])
                if name == "invoke_connector":
                    return await session.invoke(arguments["connector"], arguments["action"], arguments["resource"])
                if name == "close_connection":
                    await session.close_connection(arguments["handle"])
                    return {"closed": True}
            except Exception:
                # Raw connector and OS exceptions can include private data or local paths.
                raise ValueError("Warden 操作未完成，请检查当前任务授权或连接状态") from None
            raise ValueError("未知的 Warden 工具")

        await server.run(reader, writer, server.create_initialization_options())


def serve(socket_path):
    asyncio.run(_run(socket_path))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path,
                        default=os.environ.get("KEYHERON_WARDEN_SOCKET", "/run/keyheron/warden.sock"))
    try:
        raise SystemExit(serve(parser.parse_args().socket))
    except (OSError, RuntimeError) as error:
        parser.exit(1, f"{error}\n")
