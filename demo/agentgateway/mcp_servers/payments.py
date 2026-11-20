# demo/agentgateway/mcp_servers/payments.py
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("payments", host="0.0.0.0", port=3001)


@mcp.tool()
def refund_order(order_id: str, amount: float, account_status: str) -> dict:
    return {"ok": True, "order_id": order_id, "amount": amount, "account_status": account_status}


@mcp.tool()
def void_payment(payment_id: str) -> dict:
    return {"ok": True, "payment_id": payment_id}


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
