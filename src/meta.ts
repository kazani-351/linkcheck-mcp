// Identity of the public deployment, shared by the landing page, the MCP
// serverInfo, /health, and the user agent on every outbound request.
export const VERSION = "0.1.0";
export const PROD_ORIGIN = "https://linkcheck-mcp.kazani.workers.dev";
export const REPO_URL = "https://github.com/kazani-351/linkcheck-mcp";
// Names the project so a site owner seeing our requests in their logs knows who's asking.
export const USER_AGENT = `linkcheck-mcp/${VERSION} (+${PROD_ORIGIN})`;
