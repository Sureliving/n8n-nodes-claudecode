# 🚀 Claude Code for n8n

**Bring the power of Claude Code directly into your n8n automation workflows!**

Imagine having an AI coding assistant that can analyze your codebase, fix bugs, write new features, manage databases, interact with APIs, and automate your entire development workflow - all within n8n. That's exactly what this node enables.

[![n8n](https://img.shields.io/badge/n8n-community_node-orange.svg)](https://n8n.io/)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Powered-blue.svg)](https://claude.ai/code)
[![npm](https://img.shields.io/npm/v/@sureliving/n8n-nodes-claudecode.svg)](https://www.npmjs.com/package/@sureliving/n8n-nodes-claudecode)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)

## 🌟 What Can You Build?

### 🔧 **Automated Code Reviews**
Create workflows that automatically review pull requests, suggest improvements, and even fix issues before merging.

### 🐛 **Intelligent Bug Fixing**
Connect error monitoring tools to Claude Code - automatically diagnose and fix production issues in real-time.

### 📊 **Database Management**
Let Claude Code write complex SQL queries, optimize database schemas, and generate migration scripts based on your requirements.

### 🤖 **Self-Improving Workflows**
Build n8n workflows that can modify and improve themselves using Claude Code's capabilities.

### 📝 **Documentation Generation**
Automatically generate and update documentation for your entire codebase, APIs, or databases.

### 🔄 **Code Migration**
Automate the migration of legacy codebases to modern frameworks with intelligent refactoring.

### 🎫 **Customer Support Automation**
Transform support tickets into code fixes automatically:
- Analyze customer bug reports and reproduce issues
- Generate fixes for reported problems
- Create test cases to prevent regression
- Update documentation based on common questions
- Auto-respond with workarounds while fixes are deployed

## ⚡ Quick Start

### Prerequisites

1. **Claude Code Runtime**

This node uses `@anthropic-ai/claude-agent-sdk`, which bundles a Node-based Claude Code entrypoint. You do **not** need a global `claude` binary in `$PATH` for the node to run.

2. **Authentication**

Create an **Anthropic API** credential in n8n and select it on the Claude Code node. The API key is injected only into the spawned Claude Code process environment for that execution. The node intentionally strips any Claude/Anthropic auth environment variables from the container environment to ensure auth comes only from n8n credentials.

### Security (multi-layer protection)

This node implements multiple layers of security to prevent secret leakage:

1. **System Prompt Policy**: A mandatory security policy is always appended to the system prompt, instructing Claude to never output secrets or run dangerous commands.

2. **Command Blocking**: Dangerous Bash commands are blocked before execution, including:
   - Environment variable dumps (`env`, `printenv`, `set`, `export`)
   - Reading sensitive files (`.env`, `.netrc`, `credentials`, `/etc/shadow`)
   - Output encoding pipes (`| base64`, `| xxd`, `| gzip`, etc.)
   - Data exfiltration attempts via `curl`/`wget` with env vars

3. **File Access Control**: Reading sensitive files is blocked (`.env`, `.netrc`, `credentials`, `id_rsa`, `.pem`, `.key`).

4. **Output Redaction**: All output is scanned for secrets and redacted:
   - Known API key patterns (OpenAI, GitHub, Slack, Google, AWS)
   - JWT tokens and PEM private keys
   - Large encoded blocks (base64, hex) that could contain exfiltrated data

### Optional GitLab access (private repos)

If you configure the built-in **GitLab API** credential (`gitlabApi`) on the node, the token is injected only into the spawned Claude Code process for the duration of the execution:

- A temporary `HOME` directory is created
- A temporary `~/.netrc` is written so `git clone https://...` can authenticate
- The temp directory is removed after the node finishes

### Install in n8n

#### Option 1: Via n8n UI (Recommended)
1. Open your n8n instance
2. Go to **Settings** → **Community Nodes**
3. Click **Install a community node**
4. Enter: `@sureliving/n8n-nodes-claudecode`
5. Click **Install**
6. Restart n8n when prompted

#### Option 2: Manual Installation
```bash
cd ~/.n8n/nodes
npm install @sureliving/n8n-nodes-claudecode
# Restart n8n
```

#### Option 3: Docker
```bash
docker run -it --rm \
  -p 5678:5678 \
  -e N8N_COMMUNITY_NODE_PACKAGES=@sureliving/n8n-nodes-claudecode \
  -v ~/.n8n:/home/node/.n8n \
  n8nio/n8n
```

📦 **NPM Package**: [@sureliving/n8n-nodes-claudecode](https://www.npmjs.com/package/@sureliving/n8n-nodes-claudecode)

## 🎯 Real-World Use Cases

### 1. **GitHub Issue to Code**
```
Webhook (GitHub Issue) → Claude Code → Create PR → Notify Slack
```
Automatically implement features or fix bugs when issues are created.

### 2. **Database Query Builder**
```
Form Trigger → Claude Code → Execute Query → Send Results
```
Natural language to SQL - let non-technical users query databases safely.

### 3. **Code Quality Guardian**
```
Git Push → Claude Code → Analyze Code → Block/Approve → Notify
```
Enforce coding standards and catch issues before they reach production.

### 4. **API Integration Builder**
```
HTTP Request → Claude Code → Generate Integration → Test → Deploy
```
Automatically create integrations with third-party APIs.

### 5. **Intelligent Log Analysis**
```
Error Logs → Claude Code → Diagnose → Create Fix → Open PR
```
Turn error logs into actionable fixes automatically.

### 6. **Customer Support to Code Fix**
```
Support Ticket → Claude Code → Reproduce Issue → Generate Fix → Test → Deploy → Auto-Reply
```
Transform customer complaints into deployed fixes in minutes, not days.

## 🛠️ Powerful Features

### **Project Context Awareness**
Set a project path and Claude Code understands your entire codebase context:
- Analyzes existing code patterns
- Follows your coding standards
- Understands your architecture
- Respects your dependencies

### **Tool Arsenal**
Claude Code comes equipped with powerful built-in tools:
- 📁 **File Operations**: `Read`, `Write`, `Edit`, `MultiEdit`, `LS`, `Glob`
- 💻 **Bash Commands**: Execute shell commands (with security restrictions)
- 🔍 **Smart Search**: `Grep` for pattern matching across your codebase
- 📓 **Notebooks**: `NotebookRead`, `NotebookEdit` for Jupyter notebooks
- 🌐 **Web Access**: `WebFetch`, `WebSearch` for documentation and resources
- 🤖 **Agents**: `Task` for launching sub-agents, `TodoWrite` for task management
- 📊 **Database Access**: Via MCP servers
- 🔗 **API Integration**: GitHub, Slack, and more via MCP

### **Advanced SDK Options**
Fine-tune Claude Code's behavior with these powerful options:
- 🚫 **Disallowed Tools**: Explicitly block specific tools for security
- 🔄 **Fallback Model**: Automatically switch models when primary is overloaded
- 🧠 **Max Thinking Tokens**: Control Claude's internal reasoning depth
- 🔐 **Permission Modes**: Choose from `default`, `acceptEdits`, `bypassPermissions`, or `plan`

### **Model Context Protocol (MCP)**
Extend Claude Code with specialized capabilities:
- PostgreSQL/MySQL database access
- GitHub repository management
- Slack workspace integration
- Custom tool development

## 📋 Configuration Examples

### Simple Code Analysis
```javascript
{
  "operation": "query",
  "prompt": "Analyze this codebase and suggest performance improvements",
  "projectPath": "/path/to/your/project",
  "model": "sonnet"
}
```

### Advanced Database Operations
```javascript
{
  "operation": "query",
  "prompt": "Create an optimized query to find users who haven't logged in for 30 days",
  "projectPath": "/path/to/project",
  "model": "opus"
}
```

### Customer Support Automation
```javascript
{
  "operation": "query",
  "prompt": "Customer reports: 'Login button not working on mobile devices'\n\nAnalyze this issue, find the root cause, and create a fix",
  "projectPath": "/path/to/web-app",
  "model": "opus",
  "allowedTools": ["Read", "Write", "Edit", "Bash", "Grep"],
  "additionalOptions": {
    "systemPrompt": "Focus on mobile compatibility issues. Check responsive CSS and JavaScript event handlers."
  }
}
```

### Advanced Configuration with SDK Options
```javascript
{
  "operation": "query",
  "prompt": "Refactor this legacy code to use modern patterns",
  "projectPath": "/path/to/legacy-app",
  "model": "opus",
  "allowedTools": ["Read", "Write", "Edit", "MultiEdit", "Grep"],
  "disallowedTools": ["Bash"],  // Prevent command execution for safety
  "additionalOptions": {
    "permissionMode": "plan",  // Claude will plan before executing
    "fallbackModel": "sonnet",  // Auto-switch if Opus is overloaded
    "maxThinkingTokens": 50000,  // Allow deep reasoning for complex refactoring
    "systemPrompt": "Preserve all existing functionality while modernizing the code"
  }
}
```

With MCP configuration (`.mcp.json`):
```json
{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres", "${DATABASE_URL}"]
    }
  }
}
```

## 🔄 Workflow Patterns

### Pattern 1: Continuous Code Improvement
```
Schedule Trigger (Daily)
  ↓
Claude Code (Analyze codebase for improvements)
  ↓
Create GitHub Issues
  ↓
Assign to Team
```

### Pattern 2: Natural Language to Code
```
Slack Command
  ↓
Claude Code (Generate code from description)
  ↓
Create Pull Request
  ↓
Run Tests
  ↓
Notify Results
```

### Pattern 3: Intelligent Monitoring
```
Error Webhook
  ↓
Claude Code (Diagnose issue)
  ↓
If (Can fix automatically)
  ├─ Yes: Create Fix PR
  └─ No: Create Detailed Issue
```

## 🚦 Getting Started

### 1. **Set Up Credentials**
1. In n8n, go to **Settings** → **Credentials**
2. Create a new **Anthropic API** credential
3. Enter your Anthropic API key

### 2. **Create Your First Workflow**
1. In n8n, create a new workflow
2. Add a **Manual Trigger** node (for testing)
3. Add the **Claude Code (Credentials)** node
4. Configure:
   - **Operation**: Query
   - **Prompt**: "Analyze the code in this directory and suggest improvements"
   - **Project Path**: `/path/to/your/project`
   - **Model**: Sonnet (faster) or Opus (more powerful)
5. Click **Execute Workflow**
6. Watch Claude Code analyze your project!

### 3. **Explore Advanced Features**
- Check out the [workflow templates](./workflow-templates/) for ready-to-use examples
- See the [examples directory](./examples/) for configuration options
- Read about [MCP servers](#model-context-protocol-mcp) for database and API access

## 💡 Pro Tips

### 🎯 **Use Project Paths**
Always set a project path for better context and results:
```
/home/user/projects/my-app
```

### 🔒 **Control Tool Access**
Use the **Allowed Tools** and **Disallowed Tools** parameters in the node to control what Claude Code can do. For example, to prevent command execution, add `Bash` to Disallowed Tools.

You can also create a `.claude/settings.json` file in your project directory for additional permission rules:
```json
{
  "permissions": {
    "allow": ["Read(*)", "Write(*)"],
    "deny": ["Bash(rm -rf *)"]
  }
}
```

### 🔗 **Chain Operations**
Use "Continue" operation to build complex multi-step workflows while maintaining context.

### 📊 **Output Formats**
- **Structured**: Full details with metrics
- **Messages**: For debugging
- **Text**: Simple results for chaining

## 🤝 Community & Support

- 📖 [Documentation](https://github.com/sureliving/n8n-nodes-claudecode)
- 🐛 [Report Issues](https://github.com/sureliving/n8n-nodes-claudecode/issues)
- 💬 [Discussions](https://github.com/sureliving/n8n-nodes-claudecode/discussions)
- 🌟 [Star on GitHub](https://github.com/sureliving/n8n-nodes-claudecode)

## 📈 What's Next?

We're constantly improving! Upcoming features:
- Visual workflow builder for Claude Code operations
- Pre-built workflow templates
- Enhanced debugging tools
- More MCP server integrations

## 🔄 Development & Contributing

### Commit Conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/) and automated semantic versioning:

- `feat:` New features (minor version bump)
- `fix:` Bug fixes (patch version bump)
- `docs:` Documentation changes
- `chore:` Maintenance tasks
- `test:` Adding or updating tests

Use `npm run commit` for an interactive commit message builder.

### Release Process

Releases are **fully automated** using semantic-release:
1. Push commits to `main` branch
2. CI analyzes commit messages
3. Version is automatically bumped based on commit types
4. Package is published to npm
5. GitHub release is created with changelog

No manual version management required!

## 📄 License

MIT - Build amazing things!

---

**Ready to revolutionize your development workflow?** Install Claude Code for n8n today and join the future of automated software development!

Originally created by [Adam Holt](https://github.com/holt-web-ai) - [Original Repository](https://github.com/holt-web-ai/n8n-nodes-claudecode)

Maintained by [sureliving](https://github.com/sureliving)