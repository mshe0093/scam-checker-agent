"""MCP server tests: in-process, plus one real stdio round-trip like Claude Desktop would make."""

import asyncio
import json
import sys

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from scamcheck.mcp_server import server
from scamcheck.registry import TOOL_SPECS

MSG = "MAYBANK: account suspended, verify at http://maybank2u-secure-verify.com/login"


def test_exposes_same_tools_as_agent_minus_verdict():
    tools = asyncio.run(server.list_tools())
    assert {t.name for t in tools} == {s["name"] for s in TOOL_SPECS}
    by_name = {t.name: t for t in tools}
    assert by_name["check_domain"].annotations.open_world_hint is True
    assert all(t.annotations.read_only_hint for t in tools)


def test_offline_tool_returns_structured_tool_result():
    res = asyncio.run(server.call_tool("extract_entities", {"message": MSG}))
    assert not res.is_error
    assert res.structured_content["tool"] == "extract_entities"
    assert res.structured_content["evidence"]["claimed_orgs"][0]["id"] == "maybank"


def test_prompt_wraps_message_as_untrusted():
    prompt = asyncio.run(server.get_prompt("investigate_message", {"message": MSG}))
    text = prompt.messages[0].content.text
    assert "<suspicious_message>" in text and "untrusted" in text


def test_stdio_round_trip():
    async def run():
        params = StdioServerParameters(command=sys.executable, args=["-m", "scamcheck.mcp_server"])
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            res = await session.call_tool("match_scam_pattern", {"message": MSG})
            orgs = await session.read_resource("scamcheck://official-orgs")
            return tools, res, orgs

    tools, res, orgs = asyncio.run(run())
    assert len(tools.tools) == 6
    assert res.structured_content["evidence"]["matches"][0]["category"] == "bank_phishing"
    assert any(o["id"] == "maybank" for o in json.loads(orgs.contents[0].text)["orgs"])
