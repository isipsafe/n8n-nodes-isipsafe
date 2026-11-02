import type {
	IAuthenticateGeneric,
	Icon,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class IsIpsafeApi implements ICredentialType {
	name = 'isIpsafeApi';

	displayName = 'isIPsafe API';

	icon: Icon = { light: 'file:../icons/isipsafe.svg', dark: 'file:../icons/isipsafe.dark.svg' };

	documentationUrl = 'https://isipsafe.com/api';

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			required: true,
			default: '',
			description:
				'Your isIPsafe API key. It starts with sl_. Create one for free at https://isipsafe.com/login.',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization: '=Bearer {{$credentials.apiKey}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: 'https://isipsafe.com/api/v1',
			url: '/check',
			method: 'GET',
			qs: { ip: '1.1.1.1' },
		},
	};
}
