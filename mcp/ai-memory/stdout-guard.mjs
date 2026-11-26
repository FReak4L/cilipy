// MCP stdio servers must write ONLY JSON-RPC to stdout. mcp-ai-memory 2.0.1 logs
// diagnostics with console.log/info (e.g. on every search), which corrupts the stream.
// Redirect them to stderr without patching vendor code.
const toErr = (...args) => console.error(...args);
console.log = toErr;
console.info = toErr;
console.debug = toErr;
