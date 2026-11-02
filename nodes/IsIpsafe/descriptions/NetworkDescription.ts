import type { INodeProperties } from 'n8n-workflow';

const showForNetwork = { resource: ['network'] };

export const networkOperations: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: showForNetwork },
		options: [
			{
				name: 'Check Block',
				value: 'checkBlock',
				description: 'Get the reported addresses inside a network',
				action: 'Check a network block',
			},
		],
		default: 'checkBlock',
	},
];

export const networkFields: INodeProperties[] = [
	{
		displayName: 'Network',
		name: 'network',
		type: 'string',
		required: true,
		default: '',
		placeholder: 'e.g. 185.220.101.0/24',
		description: 'CIDR network, up to a /16 for IPv4 or a /48 for IPv6',
		displayOptions: { show: { ...showForNetwork, operation: ['checkBlock'] } },
	},
	{
		displayName: 'Options',
		name: 'checkBlockOptions',
		type: 'collection',
		placeholder: 'Add Option',
		default: {},
		displayOptions: { show: { ...showForNetwork, operation: ['checkBlock'] } },
		options: [
			{
				displayName: 'Max Age (Days)',
				name: 'maxAgeInDays',
				type: 'number',
				typeOptions: { minValue: 1, maxValue: 365 },
				default: 30,
				description: 'Only consider reports from the last this many days',
			},
		],
	},
];
