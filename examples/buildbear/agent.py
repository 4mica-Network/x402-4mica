#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import os
from typing import List, TypedDict

import httpx
from eth_account import Account
from langchain_core.messages import BaseMessage, HumanMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode

from fourmica_sdk import Client, ConfigBuilder, PaymentRequirementsV1, X402Flow

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional dependency
    load_dotenv = None


class AgentState(TypedDict):
    messages: List[BaseMessage]


def _load_env() -> None:
    if load_dotenv is None:
        return
    load_dotenv()


async def get_payer_client() -> tuple[Client, str, X402Flow]:
    _load_env()
    payer_key = os.environ["PAYER_KEY"]
    cfg = ConfigBuilder().from_env().wallet_private_key(payer_key).build()
    client = await Client.new(cfg)
    address = Account.from_key(payer_key).address
    flow = X402Flow.from_client(client)
    return client, address, flow


@tool
async def get_minion_nft() -> str:
    """Pay for and receive a pixelated minion NFT image."""
    _load_env()
    server_url = os.getenv("SERVER_URL", "http://localhost:8402").rstrip("/")
    client, address, flow = await get_payer_client()
    try:
        async with httpx.AsyncClient() as http:
            resp = await http.get(f"{server_url}/image")
            if resp.status_code != 402:
                return json.dumps({"error": "Unexpected response", "status": resp.status_code})

            body = resp.json()
            requirements_raw = body.get("paymentRequirements")
            if not isinstance(requirements_raw, dict):
                return json.dumps({"error": "Missing paymentRequirements"})

            requirements = PaymentRequirementsV1.from_raw(requirements_raw)
            payment = await flow.sign_payment(requirements, address)

            image_resp = await http.get(
                f"{server_url}/image",
                headers={"X-PAYMENT": payment.header},
            )
            return json.dumps(image_resp.json())
    finally:
        await client.aclose()


def should_continue(state: AgentState):
    last = state["messages"][-1]
    if getattr(last, "tool_calls", None):
        return "tools"
    return END


def build_agent() -> StateGraph:
    llm = ChatOpenAI(model=os.getenv("OPENAI_CHAT_MODEL", "gpt-4o"), temperature=0)
    tools = [get_minion_nft]
    llm_with_tools = llm.bind_tools(tools)

    async def agent_node(state: AgentState):
        response = await llm_with_tools.ainvoke(state["messages"])
        return {"messages": [response]}

    workflow = StateGraph(AgentState)
    workflow.add_node("agent", agent_node)
    workflow.add_node("tools", ToolNode(tools))
    workflow.set_entry_point("agent")
    workflow.add_conditional_edges("agent", should_continue)
    workflow.add_edge("tools", "agent")
    return workflow.compile()


async def main() -> None:
    prompt = os.getenv("AGENT_PROMPT")
    if not prompt:
        prompt = input("You: ").strip() or "get me a minion"
    graph = build_agent()
    result = await graph.ainvoke({"messages": [HumanMessage(content=prompt)]})
    messages = result["messages"]
    print(messages[-1].content)


if __name__ == "__main__":
    asyncio.run(main())
