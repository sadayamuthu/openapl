# demo/agentgateway/mcp_servers/crm.py
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("crm", host="0.0.0.0", port=3002)


@mcp.tool()
def export_customers() -> dict:
    return {"ok": True}


@mcp.tool()
def get_customer(customer_id: str) -> dict:
    return {"ok": True, "customer_id": customer_id}


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
