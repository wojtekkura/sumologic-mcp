from mcp.server.fastmcp import FastMCP

from sumologic_mcp.clients import state
from sumologic_mcp.tools.attach_note import attach_note
from sumologic_mcp.tools.claim_incident import claim_incident
from sumologic_mcp.tools.list_new_insights import list_new_insights

mcp = FastMCP("sumologic-mcp")
mcp.add_tool(claim_incident)
mcp.add_tool(attach_note)
mcp.add_tool(list_new_insights)


def run_stdio() -> None:
    state.init()
    mcp.run(transport="stdio")
