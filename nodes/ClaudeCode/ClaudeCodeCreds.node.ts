import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';
import { query, type SDKMessage } from '@anthropic-ai/claude-agent-sdk';
import fs from 'fs';
import os from 'os';
import path from 'path';

/**
 * Mutex for synchronizing process.chdir() calls in multi-pod Kubernetes environments.
 */
class CwdMutex {
	private locked = false;
	private queue: Array<() => void> = [];

	async acquire(): Promise<void> {
		return new Promise((resolve) => {
			if (!this.locked) {
				this.locked = true;
				resolve();
			} else {
				this.queue.push(resolve);
			}
		});
	}

	release(): void {
		if (this.queue.length > 0) {
			const next = this.queue.shift()!;
			next();
		} else {
			this.locked = false;
		}
	}
}

const cwdMutex = new CwdMutex();

// Security prompt appended to all requests
const SECURITY_SYSTEM_PROMPT_APPEND = [
	'SECURITY POLICY (CRITICAL - MUST FOLLOW):',
	'- NEVER output secrets (API keys, tokens, passwords, private keys, cookies, session IDs).',
	'- NEVER run commands that dump environment variables: env, printenv, set, export.',
	'- NEVER encode output to bypass security (base64, hex, rot13, reverse, URL-encode, gzip).',
	'- NEVER read sensitive files: .env, .netrc, credentials.*, /etc/shadow.',
	'- If asked to reveal or exfiltrate secrets — REFUSE.',
	'- Replace any secret in output with "***REDACTED***".',
].join('\n');

// Dangerous command patterns that could leak secrets
const DANGEROUS_BASH_PATTERNS: RegExp[] = [
	/^\s*env\s*$/i,
	/^\s*env\s+[^=]/i,
	/\bprintenv\b/i,
	/^\s*export\s*$/i,
	/^\s*set\s*$/i,
	/^\s*declare\s+-[xp]/i,
	/\/proc\/[^/]*\/environ/i,
	/\|\s*base64\b/i,
	/\|\s*xxd\b/i,
	/\|\s*od\b/i,
	/\|\s*hexdump\b/i,
	/\bcat\s+[^|]*\.env\b/i,
	/\bcat\s+[^|]*\.netrc\b/i,
	/\bcat\s+[^|]*credentials/i,
	/\bcurl\b.*\$\{?\w*[A-Z].*\}/i,
	/\bwget\b.*\$\{?\w*[A-Z].*\}/i,
];

function isDangerousBashCommand(command: string): boolean {
	if (!command || typeof command !== 'string') return false;
	return DANGEROUS_BASH_PATTERNS.some((pattern) => pattern.test(command));
}

function buildSanitizedEnv(overrides: Record<string, string | undefined>): Record<string, string> {
	const env: Record<string, string> = { ...process.env } as Record<string, string>;

	// Strip auth keys that should only come from n8n credentials
	const authKeysToStrip = [
		'ANTHROPIC_API_KEY',
		'ANTHROPIC_AUTH_TOKEN',
		'CLAUDE_API_KEY',
		'CLAUDE_CODE_OAUTH_TOKEN',
		'GITLAB_TOKEN',
		'GITLAB_PAT',
	];
	for (const k of authKeysToStrip) delete env[k];

	for (const [k, v] of Object.entries(overrides)) {
		if (typeof v === 'string' && v.length > 0) env[k] = v;
	}
	return env;
}

function hostFromGitlabServer(server: string): string {
	const trimmed = server.trim();
	if (!trimmed) return 'gitlab.com';
	try {
		const url = trimmed.includes('://') ? new URL(trimmed) : new URL(`https://${trimmed}`);
		return url.hostname;
	} catch {
		return trimmed.replace(/^https?:\/\//, '').split('/')[0] || 'gitlab.com';
	}
}

function writeNetrc(homeDir: string, host: string, token: string) {
	const netrcPath = path.join(homeDir, '.netrc');
	fs.writeFileSync(netrcPath, `machine ${host}\nlogin oauth2\npassword ${token}\n`, {
		mode: 0o600,
	});
}

function toBase64(input: string): string {
	return Buffer.from(input, 'utf8').toString('base64');
}

function toBase64Url(input: string): string {
	return toBase64(input).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function reverseString(input: string): string {
	return input.split('').reverse().join('');
}

function uniqueNonEmpty(values: string[]): string[] {
	const seen = new Set<string>();
	return values.filter((v) => {
		const s = (v ?? '').trim();
		if (!s || seen.has(s)) return false;
		seen.add(s);
		return true;
	});
}

function redactString(input: string, secrets: string[]): string {
	let out = input;
	for (const secret of secrets) {
		if (secret) out = out.split(secret).join('***REDACTED***');
	}
	return out;
}

function redactByRegex(input: string): string {
	const patterns: RegExp[] = [
		// OpenAI / Anthropic
		/\bsk-[A-Za-z0-9_-]{16,}\b/g,
		// GitHub PAT
		/\bghp_[A-Za-z0-9]{30,}\b/g,
		// GitHub OAuth/User/Server/App tokens
		/\bgh[osup]_[A-Za-z0-9]{30,}\b/g,
		// GitLab PAT
		/\bglpat-[A-Za-z0-9_-]{20,}\b/g,
		// Slack
		/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
		// Google API
		/\bAIza[0-9A-Za-z_-]{30,}\b/g,
		// AWS Access Key
		/\bAKIA[0-9A-Z]{16}\b/g,
		// Stripe live/restricted keys
		/\b[sr]k_live_[A-Za-z0-9]{20,}\b/g,
		// npm tokens
		/\bnpm_[A-Za-z0-9]{30,}\b/g,
		// JWT tokens
		/\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g,
		// Bearer tokens in headers
		/\bBearer\s+[A-Za-z0-9_-]{20,}\b/gi,
		// Credentials in URLs (user:pass@host)
		/:\/\/[^:]+:[^@]+@/g,
		// Private keys (PEM format)
		/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
		// Long base64 strings (likely encoded secrets)
		/[A-Za-z0-9+/]{200,}={0,2}/g,
	];
	let out = input;
	for (const re of patterns) out = out.replace(re, '***REDACTED***');
	return out;
}

function redactSecretsDeep<T>(value: T, secrets: string[]): T {
	if (value === null || value === undefined) return value;
	if (typeof value === 'string') return redactByRegex(redactString(value, secrets)) as unknown as T;
	if (typeof value !== 'object') return value;
	if (Array.isArray(value)) return value.map((v) => redactSecretsDeep(v, secrets)) as unknown as T;
	const out: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
		out[k] = redactSecretsDeep(v, secrets);
	}
	return out as T;
}

/**
 * Find session file and extract cwd from it.
 */
function findSessionInfo(
	sessionId: string,
	projectPath?: string,
): { sessionFile: string; cwd: string } | null {
	const projectsDir = path.join(os.homedir(), '.claude', 'projects');
	if (!fs.existsSync(projectsDir)) return null;

	// If projectPath specified, check there first
	if (projectPath) {
		const encodedPath = projectPath.replace(/\//g, '-');
		const sessionFile = path.join(projectsDir, encodedPath, `${sessionId}.jsonl`);
		if (fs.existsSync(sessionFile)) {
			return { sessionFile, cwd: projectPath };
		}
	}

	// Search all project directories
	for (const dir of fs.readdirSync(projectsDir)) {
		const sessionFile = path.join(projectsDir, dir, `${sessionId}.jsonl`);
		if (fs.existsSync(sessionFile)) {
			try {
				const content = fs.readFileSync(sessionFile, 'utf-8');
				for (const line of content.split('\n')) {
					if (!line.trim()) continue;
					const entry = JSON.parse(line);
					if (entry.cwd) return { sessionFile, cwd: entry.cwd };
				}
			} catch {
				// Fall back to decoded directory name
			}
			return { sessionFile, cwd: dir.replace(/-/g, '/') };
		}
	}
	return null;
}

/**
 * Ensure session is in sessions-index.json for SDK to find it.
 */
function ensureSessionInIndex(sessionFile: string, sessionId: string, cwd: string): void {
	const encodedPath = cwd.replace(/\//g, '-');
	const claudeDir = path.join(os.homedir(), '.claude', 'projects', encodedPath);
	const indexPath = path.join(claudeDir, 'sessions-index.json');

	let index: { version: number; entries: any[]; originalPath: string } = {
		version: 1,
		entries: [],
		originalPath: cwd,
	};

	if (fs.existsSync(indexPath)) {
		try {
			index = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
			if (index.entries.some((e) => e.sessionId === sessionId)) return;
		} catch {
			// Recreate index
		}
	}

	const stats = fs.statSync(sessionFile);
	index.entries.push({
		sessionId,
		fullPath: sessionFile,
		fileMtime: stats.mtimeMs,
		firstPrompt: 'Continue session',
		messageCount: 0,
		created: new Date().toISOString(),
		modified: stats.mtime.toISOString(),
		gitBranch: '',
		projectPath: cwd,
		isSidechain: false,
	});
	index.originalPath = cwd;

	if (!fs.existsSync(claudeDir)) fs.mkdirSync(claudeDir, { recursive: true });
	fs.writeFileSync(indexPath, JSON.stringify(index, null, 2));
}

export class ClaudeCodeCreds implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Claude Code (Credentials)',
		name: 'claudeCodeCreds',
		icon: 'file:claudecode.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["prompt"]}}',
		description:
			'Use Claude Code SDK to execute AI-powered coding tasks with authentication from n8n credentials',
		defaults: { name: 'Claude Code' },
		credentials: [
			{ name: 'anthropicApi', required: true },
			{ name: 'gitlabApi', required: false },
		],
		inputs: [{ type: 'main' }],
		outputs: [{ type: 'main' }],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Query',
						value: 'query',
						description: 'Start a new conversation with Claude Code',
						action: 'Start a new conversation with claude code',
					},
					{
						name: 'Continue',
						value: 'continue',
						description: 'Continue a previous conversation',
						action: 'Continue a previous conversation requires prior query',
					},
				],
				default: 'query',
			},
			{
				displayName: 'Session ID',
				name: 'sessionId',
				type: 'string',
				default: '',
				description: 'The session ID from a previous Query response',
				required: true,
				placeholder: 'e.g., "abc123-def456-..."',
				hint: 'Use {{$json.session_id}} to get from previous Query',
				displayOptions: { show: { operation: ['continue'] } },
			},
			{
				displayName: 'Prompt',
				name: 'prompt',
				type: 'string',
				typeOptions: { rows: 4 },
				default: '',
				description: 'The prompt to send to Claude Code',
				required: true,
				placeholder: 'e.g., "Create a Python function to parse CSV files"',
			},
			{
				displayName: 'Model',
				name: 'model',
				type: 'options',
				options: [
					{ name: 'Sonnet', value: 'sonnet', description: 'Fast and efficient' },
					{ name: 'Opus', value: 'opus', description: 'Most capable' },
				],
				default: 'sonnet',
				description: 'Claude model to use',
			},
			{
				displayName: 'Max Turns',
				name: 'maxTurns',
				type: 'number',
				default: 25,
				description: 'Maximum conversation turns allowed',
			},
			{
				displayName: 'Timeout',
				name: 'timeout',
				type: 'number',
				default: 300,
				description: 'Maximum time in seconds before aborting',
			},
			{
				displayName: 'Project Path',
				name: 'projectPath',
				type: 'string',
				default: '',
				description: 'Working directory for Claude Code',
				placeholder: '/home/user/projects/my-app',
			},
			{
				displayName: 'Output Format',
				name: 'outputFormat',
				type: 'options',
				noDataExpression: true,
				options: [
					{ name: 'Structured', value: 'structured', description: 'Full structured output' },
					{ name: 'Messages', value: 'messages', description: 'Raw messages array' },
					{ name: 'Text', value: 'text', description: 'Final result text only' },
				],
				default: 'structured',
			},
			{
				displayName: 'Allowed Tools',
				name: 'allowedTools',
				type: 'multiOptions',
				options: [
					{ name: 'Bash', value: 'Bash' },
					{ name: 'Edit', value: 'Edit' },
					{ name: 'Glob', value: 'Glob' },
					{ name: 'Grep', value: 'Grep' },
					{ name: 'LS', value: 'LS' },
					{ name: 'MultiEdit', value: 'MultiEdit' },
					{ name: 'Notebook Edit', value: 'NotebookEdit' },
					{ name: 'Notebook Read', value: 'NotebookRead' },
					{ name: 'Read', value: 'Read' },
					{ name: 'Task', value: 'Task' },
					{ name: 'Todo Write', value: 'TodoWrite' },
					{ name: 'Web Fetch', value: 'WebFetch' },
					{ name: 'Web Search', value: 'WebSearch' },
					{ name: 'Write', value: 'Write' },
				],
				default: ['WebFetch', 'TodoWrite', 'WebSearch', 'Task'],
				description: 'Tools Claude Code is allowed to use',
			},
			{
				displayName: 'Disallowed Tools',
				name: 'disallowedTools',
				type: 'multiOptions',
				options: [
					{ name: 'Bash', value: 'Bash' },
					{ name: 'Edit', value: 'Edit' },
					{ name: 'Glob', value: 'Glob' },
					{ name: 'Grep', value: 'Grep' },
					{ name: 'LS', value: 'LS' },
					{ name: 'MultiEdit', value: 'MultiEdit' },
					{ name: 'Notebook Edit', value: 'NotebookEdit' },
					{ name: 'Notebook Read', value: 'NotebookRead' },
					{ name: 'Read', value: 'Read' },
					{ name: 'Task', value: 'Task' },
					{ name: 'Todo Write', value: 'TodoWrite' },
					{ name: 'Web Fetch', value: 'WebFetch' },
					{ name: 'Web Search', value: 'WebSearch' },
					{ name: 'Write', value: 'Write' },
				],
				default: [],
				description: 'Tools explicitly blocked (takes precedence)',
			},
			{
				displayName: 'Additional Options',
				name: 'additionalOptions',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				options: [
					{
						displayName: 'Debug Mode',
						name: 'debug',
						type: 'boolean',
						default: false,
						description: 'Whether to enable debug logging',
					},
					{
						displayName: 'Permission Mode',
						name: 'permissionMode',
						type: 'options',
						options: [
							{ name: 'Default', value: 'default' },
							{ name: 'Accept Edits', value: 'acceptEdits' },
							{ name: 'Bypass Permissions', value: 'bypassPermissions' },
							{ name: 'Plan', value: 'plan' },
						],
						default: 'bypassPermissions',
						description: 'How to handle permission requests',
					},
					{
						displayName: 'System Prompt',
						name: 'systemPrompt',
						type: 'string',
						typeOptions: { rows: 4 },
						default: '',
						description: 'Additional instructions for Claude',
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			let gitlabTempHome: string | undefined;
			const timeout = this.getNodeParameter('timeout', itemIndex, 300) as number;

			try {
				const operation = this.getNodeParameter('operation', itemIndex) as string;
				const prompt = this.getNodeParameter('prompt', itemIndex) as string;
				const model = this.getNodeParameter('model', itemIndex) as string;
				const maxTurns = this.getNodeParameter('maxTurns', itemIndex) as number;
				const projectPath = this.getNodeParameter('projectPath', itemIndex) as string;
				const outputFormat = this.getNodeParameter('outputFormat', itemIndex) as string;
				const allowedTools = this.getNodeParameter('allowedTools', itemIndex, []) as string[];
				const disallowedTools = this.getNodeParameter('disallowedTools', itemIndex, []) as string[];
				const additionalOptions = this.getNodeParameter('additionalOptions', itemIndex) as {
					systemPrompt?: string;
					permissionMode?: string;
					debug?: boolean;
				};

				if (!prompt?.trim()) {
					throw new NodeOperationError(this.getNode(), 'Prompt is required', { itemIndex });
				}

				const abortController = new AbortController();
				const timeoutId = setTimeout(() => abortController.abort(), timeout * 1000);

				// Get credentials
				const credentials = (await this.getCredentials('anthropicApi')) as { apiKey?: string };
				const apiKey = credentials.apiKey?.trim();
				if (!apiKey) {
					throw new NodeOperationError(this.getNode(), 'Anthropic API Key is required', {
						itemIndex,
					});
				}

				let gitlabToken: string | undefined;
				let gitlabHost: string | undefined;
				try {
					const gitlabCreds = (await this.getCredentials('gitlabApi')) as {
						server?: string;
						accessToken?: string;
					};
					gitlabToken = gitlabCreds.accessToken?.trim();
					gitlabHost = hostFromGitlabServer(gitlabCreds.server ?? '');
				} catch {
					// GitLab not configured
				}

				// Build secrets list for redaction
				const secretsToRedact = uniqueNonEmpty([
					apiKey,
					reverseString(apiKey),
					toBase64(apiKey),
					toBase64Url(apiKey),
					...(gitlabToken
						? [
								gitlabToken,
								reverseString(gitlabToken),
								toBase64(gitlabToken),
								toBase64Url(gitlabToken),
							]
						: []),
				]);

				// Build environment
				const envOverrides: Record<string, string | undefined> = {
					ANTHROPIC_API_KEY: apiKey,
					GIT_TERMINAL_PROMPT: '0',
				};

				if (gitlabToken && gitlabHost) {
					gitlabTempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'n8n-claude-gitlab-'));
					writeNetrc(gitlabTempHome, gitlabHost, gitlabToken);

					// Symlink .claude folder so sessions are accessible
					const realClaudeDir = path.join(os.homedir(), '.claude');
					const tempClaudeDir = path.join(gitlabTempHome, '.claude');
					try {
						if (fs.existsSync(realClaudeDir)) {
							fs.symlinkSync(realClaudeDir, tempClaudeDir);
						}
					} catch {
						// Non-fatal - Continue may not work but GitLab auth will
					}
					envOverrides.HOME = gitlabTempHome;
				}

				// Determine effective cwd
				let effectiveCwd = projectPath?.trim() || '';

				if (operation === 'continue') {
					const sessionId = (this.getNodeParameter('sessionId', itemIndex) as string)?.trim();
					if (!sessionId) {
						throw new NodeOperationError(this.getNode(), 'Session ID is required for Continue', {
							itemIndex,
						});
					}

					const sessionInfo = findSessionInfo(sessionId, projectPath?.trim());
					if (!sessionInfo) {
						throw new NodeOperationError(this.getNode(), `Session not found: ${sessionId}`, {
							itemIndex,
							description:
								'Session file not found. Ensure Query and Continue run on the same pod or use shared storage.',
						});
					}

					effectiveCwd = sessionInfo.cwd;
					ensureSessionInIndex(sessionInfo.sessionFile, sessionId, effectiveCwd);
				}

				// Build query options
				const queryOptions: any = {
					prompt,
					abortController,
					options: {
						maxTurns,
						permissionMode: additionalOptions.permissionMode || 'bypassPermissions',
						model,
						systemPrompt: {
							type: 'preset',
							preset: 'claude_code',
							append: [SECURITY_SYSTEM_PROMPT_APPEND, additionalOptions.systemPrompt]
								.filter(Boolean)
								.join('\n\n'),
						},
						env: buildSanitizedEnv(envOverrides),
						canUseTool: async (toolName: string, input: Record<string, unknown>) => {
							if (toolName === 'Bash' && isDangerousBashCommand((input?.command as string) || '')) {
								return { behavior: 'deny', message: 'Command blocked for security.' };
							}
							if (toolName === 'Read') {
								const filePath = ((input?.file_path as string) || '').toLowerCase();
								const blocked = ['.env', '.netrc', 'credentials', '/etc/shadow', 'id_rsa'];
								if (blocked.some((p) => filePath.includes(p))) {
									return { behavior: 'deny', message: 'File blocked for security.' };
								}
							}
							return { behavior: 'allow', updatedInput: input };
						},
					},
				};

				if (effectiveCwd) queryOptions.options.cwd = effectiveCwd;

				// Load MCP servers from .mcp.json if present in project directory
				if (effectiveCwd) {
					const mcpJsonPath = path.join(effectiveCwd, '.mcp.json');
					if (fs.existsSync(mcpJsonPath)) {
						try {
							const mcpConfig = JSON.parse(fs.readFileSync(mcpJsonPath, 'utf8'));
							if (mcpConfig.mcpServers && typeof mcpConfig.mcpServers === 'object') {
								queryOptions.options.mcpServers = mcpConfig.mcpServers;
								if (additionalOptions.debug) {
									this.logger.info(
										`[Claude Code] Loaded MCP servers from ${mcpJsonPath}: ${Object.keys(mcpConfig.mcpServers).join(', ')}`,
									);
								}
							}
						} catch (e) {
							if (additionalOptions.debug) {
								this.logger.warn(`[Claude Code] Failed to parse ${mcpJsonPath}: ${e}`);
							}
						}
					}
				}

				if (allowedTools.length > 0) queryOptions.options.allowedTools = allowedTools;
				if (disallowedTools.length > 0) queryOptions.options.disallowedTools = disallowedTools;

				if (operation === 'continue') {
					queryOptions.options.resume = (
						this.getNodeParameter('sessionId', itemIndex) as string
					).trim();
				}

				// Execute with cwd workaround (SDK ignores cwd option)
				const messages: SDKMessage[] = [];
				const startTime = Date.now();
				const needsChdirWorkaround = !!effectiveCwd;
				let originalCwd: string | undefined;

				if (needsChdirWorkaround) {
					await cwdMutex.acquire();
					originalCwd = process.cwd();
					try {
						process.chdir(effectiveCwd);
					} catch (e) {
						cwdMutex.release();
						throw new NodeOperationError(
							this.getNode(),
							`Failed to change directory: ${effectiveCwd}`,
							{ itemIndex },
						);
					}
				}

				try {
					for await (const message of query(queryOptions)) {
						messages.push(message);

						if (additionalOptions.debug && message.type === 'result') {
							this.logger.info(
								`[Claude Code] Result: ${JSON.stringify(message).substring(0, 500)}`,
							);
						}
					}

					clearTimeout(timeoutId);

					// Format output
					const resultMsg = messages.find((m) => m.type === 'result') as any;
					const sessionId = resultMsg?.session_id || null;

					if (outputFormat === 'text') {
						let finalText = resultMsg?.result || resultMsg?.error || '';
						if (!finalText && resultMsg?.subtype === 'error_max_turns') {
							finalText = 'Error: Maximum turns reached. Increase maxTurns.';
						}
						returnData.push({
							json: {
								result: redactByRegex(redactString(String(finalText), secretsToRedact)),
								success: resultMsg?.subtype === 'success',
								duration_ms: resultMsg?.duration_ms || Date.now() - startTime,
								total_cost_usd: resultMsg?.total_cost_usd || 0,
								session_id: sessionId,
							},
							pairedItem: { item: itemIndex },
						});
					} else if (outputFormat === 'messages') {
						returnData.push({
							json: {
								messages: redactSecretsDeep(messages, secretsToRedact),
								messageCount: messages.length,
								session_id: sessionId,
							},
							pairedItem: { item: itemIndex },
						});
					} else {
						// structured
						const systemInit = messages.find(
							(m) => m.type === 'system' && (m as any).subtype === 'init',
						) as any;
						returnData.push({
							json: {
								messages: redactSecretsDeep(messages, secretsToRedact),
								summary: {
									userMessageCount: messages.filter((m) => m.type === 'user').length,
									assistantMessageCount: messages.filter((m) => m.type === 'assistant').length,
									toolUseCount: messages.filter(
										(m) =>
											m.type === 'assistant' &&
											(m as any).message?.content?.[0]?.type === 'tool_use',
									).length,
									toolsAvailable: systemInit?.tools || [],
								},
								result: redactSecretsDeep(
									resultMsg?.result || resultMsg?.error || null,
									secretsToRedact,
								),
								metrics: resultMsg
									? {
											duration_ms: resultMsg.duration_ms,
											num_turns: resultMsg.num_turns,
											total_cost_usd: resultMsg.total_cost_usd,
											usage: resultMsg.usage,
										}
									: null,
								success: resultMsg?.subtype === 'success',
								session_id: sessionId,
							},
							pairedItem: { item: itemIndex },
						});
					}
				} finally {
					if (needsChdirWorkaround && originalCwd) {
						try {
							process.chdir(originalCwd);
						} catch {
							// Ignore
						} finally {
							cwdMutex.release();
						}
					}
				}
			} catch (error) {
				const errorMessage = error instanceof Error ? error.message : 'Unknown error';
				const isTimeout = error instanceof Error && error.name === 'AbortError';

				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: errorMessage,
							errorType: isTimeout ? 'timeout' : 'execution_error',
							itemIndex,
						},
						pairedItem: itemIndex,
					});
					continue;
				}

				throw new NodeOperationError(
					this.getNode(),
					isTimeout ? `Timed out after ${timeout}s` : `Execution failed: ${errorMessage}`,
					{ itemIndex },
				);
			} finally {
				if (gitlabTempHome) {
					try {
						fs.rmSync(gitlabTempHome, { recursive: true, force: true });
					} catch {
						// Ignore
					}
				}
			}
		}

		return [returnData];
	}
}
