import type { INodeProperties } from 'n8n-workflow';

const showForBulkReport = { resource: ['bulk'], operation: ['report'] };

export const bulkOperations: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['bulk'] } },
		options: [
			{
				name: 'Report',
				value: 'report',
				description:
					'Report every input item in one upload of up to 10,000 rows (larger inputs are split into several uploads)',
				action: 'Report many IP addresses at once',
			},
		],
		default: 'report',
	},
];

export const bulkFields: INodeProperties[] = [
	{
		displayName:
			'Each input item becomes one report. Map the fields below to your data, for example with an expression such as {{ $json.ip }}.',
		name: 'bulkNotice',
		type: 'notice',
		default: '',
		displayOptions: { show: showForBulkReport },
	},
	{
		displayName: 'IP Address or Network',
		name: 'ip',
		type: 'string',
		required: true,
		default: '={{ $json.ip }}',
		description: 'IPv4 or IPv6 address, or a CIDR network, for each item',
		displayOptions: { show: showForBulkReport },
	},
	{
		displayName: 'Categories',
		name: 'categories',
		type: 'string',
		required: true,
		default: '={{ $json.categories }}',
		placeholder: 'e.g. ssh,brute-force',
		description: 'Comma-separated category slugs or IDs, or an array of them, for each item',
		displayOptions: { show: showForBulkReport },
	},
	{
		displayName: 'Attack Time',
		name: 'timestamp',
		type: 'string',
		default: '',
		placeholder: 'e.g. {{ $json.timestamp }}',
		description:
			'Optional ISO 8601 time of the attack for each item. Times without a time zone are read as UTC.',
		displayOptions: { show: showForBulkReport },
	},
	{
		displayName: 'Comment',
		name: 'comment',
		type: 'string',
		default: '',
		placeholder: 'e.g. {{ $json.message }}',
		description:
			'Optional public comment for each item, up to 1024 characters. Leave out personal data.',
		displayOptions: { show: showForBulkReport },
	},
];
