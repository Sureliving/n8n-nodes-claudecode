import type { ICredentialType, INodeProperties } from 'n8n-workflow';

export class GitlabApi implements ICredentialType {
	name = 'gitlabApi';
	displayName = 'GitLab API';
	documentationUrl = 'https://docs.gitlab.com/user/profile/personal_access_tokens/';

	properties: INodeProperties[] = [
		{
			displayName: 'Host',
			name: 'host',
			type: 'string',
			default: 'gitlab.com',
			description: 'GitLab host (e.g. gitlab.com or gitlab.example.com).',
			required: true,
		},
		{
			displayName: 'Personal Access Token',
			name: 'token',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
		},
	];
}
