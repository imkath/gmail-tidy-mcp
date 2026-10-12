#!/usr/bin/env node
// No arguments: runs the MCP server over stdio (this is what your MCP client launches).
// With arguments: manage accounts from the terminal.
//   gmail-tidy-mcp add <email> [label]
//   gmail-tidy-mcp remove <email>
//   gmail-tidy-mcp list

const [cmd, email, label] = process.argv.slice(2);

if (!cmd) {
  const { createServer } = await import('../src/server.js');
  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  await createServer().connect(new StdioServerTransport());
} else {
  const store = await import('../src/store.js');
  if (cmd === 'add' && email) {
    const { startLogin, openBrowser } = await import('../src/auth.js');
    const { url, result } = await startLogin(email);
    console.log(`Sign in as ${email} here:\n${url}\n`);
    openBrowser(url);
    const granted = await result;
    store.saveAccount(granted.email, granted.tokens, label);
    console.log(`Connected ${granted.email}${label ? ` (${label})` : ''}.`);
  } else if (cmd === 'remove' && email) {
    store.removeAccount(email);
    console.log(`Removed ${email}. To revoke it on Google's side too: https://myaccount.google.com/permissions`);
  } else if (cmd === 'list') {
    for (const a of store.listAccounts()) console.log(`${(a.label ?? '-').padEnd(16)} ${a.email}`);
  } else {
    console.error('Usage: gmail-tidy-mcp add <email> [label] | remove <email> | list');
    process.exit(1);
  }
}
