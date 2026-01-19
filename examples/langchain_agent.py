#!/usr/bin/env python3
"""Example: LangChain Agent with TrustChain.

This example shows how to integrate TrustChain with LangChain agents
for cryptographically verified tool execution.

Requirements:
    pip install langchain langchain-openai

Usage:
    export OPENAI_API_KEY=your_key
    python examples/langchain_agent.py
"""

from trustchain import TrustChain
from trustchain.integrations.langchain import to_langchain_tools

# Initialize TrustChain
tc = TrustChain()


@tc.tool("search")
def search_web(query: str, max_results: int = 5) -> dict:
    """Search the web for information.

    Args:
        query: Search query string
        max_results: Maximum number of results to return
    """
    # Demo - in production use real search API
    results = [
        {"title": f"Result {i+1} for '{query}'", "url": f"https://example.com/{i}"}
        for i in range(max_results)
    ]
    return {"query": query, "results": results}


@tc.tool("get_stock_price")
def get_stock_price(symbol: str) -> dict:
    """Get current stock price.

    Args:
        symbol: Stock ticker symbol (e.g., "AAPL", "GOOGL")
    """
    # Demo data
    prices = {
        "AAPL": 185.50,
        "GOOGL": 142.30,
        "MSFT": 378.90,
        "AMZN": 182.75,
        "TSLA": 245.60,
    }
    return {
        "symbol": symbol,
        "price": prices.get(symbol.upper(), 100.00),
        "currency": "USD",
    }


@tc.tool("send_email")
def send_email(to: str, subject: str, body: str) -> dict:
    """Send an email (demo, doesn't actually send).

    Args:
        to: Recipient email address
        subject: Email subject line
        body: Email body content
    """
    # Demo - in production integrate with real email service
    return {
        "status": "sent",
        "to": to,
        "subject": subject,
        "message_id": "msg_12345",
    }


def main():
    """Run the LangChain agent with TrustChain tools."""

    # Convert TrustChain tools to LangChain format
    lc_tools = to_langchain_tools(tc)

    print("🔐 TrustChain + LangChain Integration")
    print(f"   Tools: {[t.name for t in lc_tools]}")
    print()

    # Show tool schemas
    for tool in lc_tools:
        print(f"   📌 {tool.name}: {tool.description[:50]}...")
    print()

    # Demo: Execute a tool directly
    print("🧪 Direct tool execution test:")
    result = get_stock_price("AAPL")
    print(f"   get_stock_price('AAPL') = {result.data}")
    print(f"   Signature: {result.signature[:32]}...")
    print()

    # To use with actual LangChain agent:
    print("💡 To use with LangChain agent:")
    print(
        """
    from langchain_openai import ChatOpenAI
    from langchain.agents import create_tool_calling_agent, AgentExecutor
    from langchain_core.prompts import ChatPromptTemplate
    
    llm = ChatOpenAI(model="gpt-4")
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful assistant. Use tools when needed."),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])
    
    agent = create_tool_calling_agent(llm, lc_tools, prompt)
    executor = AgentExecutor(agent=agent, tools=lc_tools)
    
    # All tool responses will be cryptographically signed!
    result = executor.invoke({"input": "What is AAPL stock price?"})
    """
    )


if __name__ == "__main__":
    main()
