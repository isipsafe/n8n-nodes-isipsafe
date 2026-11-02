import type { INodeProperties } from 'n8n-workflow';

const showForIp = { resource: ['ip'] };

const maxAgeInDays: INodeProperties = {
	displayName: 'Max Age (Days)',
	name: 'maxAgeInDays',
	type: 'number',
	typeOptions: { minValue: 1, maxValue: 365 },
	default: 30,
	description: 'Only consider reports from the last this many days',
};

export const ipOperations: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: showForIp },
		options: [
			{
				name: 'Check',
				value: 'check',
				description:
					'Get the abuse confidence score, report counts, location and network of an IP address',
				action: 'Check an IP address',
			},
			{
				name: 'Clear Reports',
				value: 'clearReports',
				description: 'Delete every report your account filed against an IP address',
				action: 'Clear your reports for an IP address',
			},
			{
				name: 'Get Reports',
				value: 'getReports',
				description: 'Get the reports filed against an IP address, newest first',
				action: 'Get reports for an IP address',
			},
			{
				name: 'Report',
				value: 'report',
				description: 'Report an abusive IP address or CIDR network',
				action: 'Report an IP address',
			},
		],
		default: 'check',
	},
];

export const ipFields: INodeProperties[] = [
	{
		displayName: 'IP Address',
		name: 'ip',
		type: 'string',
		required: true,
		default: '',
		placeholder: 'e.g. 185.220.101.1',
		description: 'IPv4 or IPv6 address',
		displayOptions: { show: { ...showForIp, operation: ['check', 'getReports'] } },
	},
	{
		displayName: 'IP Address or Network',
		name: 'ip',
		type: 'string',
		required: true,
		default: '',
		placeholder: 'e.g. 203.0.113.50',
		description: 'IPv4 or IPv6 address, or a CIDR network up to a /24 (IPv4) or /56 (IPv6)',
		displayOptions: { show: { ...showForIp, operation: ['report', 'clearReports'] } },
	},
	{
		displayName: 'Options',
		name: 'checkOptions',
		type: 'collection',
		placeholder: 'Add Option',
		default: {},
		displayOptions: { show: { ...showForIp, operation: ['check'] } },
		options: [
			{
				displayName: 'Malicious Threshold',
				name: 'threshold',
				type: 'number',
				typeOptions: { minValue: 1, maxValue: 100 },
				default: 75,
				description:
					'Score at or above which the output field isMalicious is true. Addresses without reports and allowlisted addresses are never malicious.',
			},
			maxAgeInDays,
			{
				displayName: 'Include Reports',
				name: 'verbose',
				type: 'boolean',
				default: false,
				description: 'Whether to include the individual reports in the result',
			},
		],
	},
	{
		displayName: 'Return All',
		name: 'returnAll',
		type: 'boolean',
		default: false,
		description: 'Whether to return all results or only up to a given limit',
		displayOptions: { show: { ...showForIp, operation: ['getReports'] } },
	},
	{
		displayName: 'Limit',
		name: 'limit',
		type: 'number',
		typeOptions: { minValue: 1 },
		default: 50,
		description: 'Max number of results to return',
		displayOptions: { show: { ...showForIp, operation: ['getReports'], returnAll: [false] } },
	},
	{
		displayName: 'Options',
		name: 'reportsOptions',
		type: 'collection',
		placeholder: 'Add Option',
		default: {},
		displayOptions: { show: { ...showForIp, operation: ['getReports'] } },
		options: [maxAgeInDays],
	},
	{
		displayName: 'Category Names or IDs',
		name: 'categories',
		type: 'multiOptions',
		required: true,
		typeOptions: { loadOptionsMethod: 'getCategories' },
		default: [],
		description:
			'Up to 12 categories that describe the abuse. Choose from the list, or specify IDs using an <a href="https://docs.n8n.io/code/expressions/">expression</a>.',
		displayOptions: { show: { ...showForIp, operation: ['report'] } },
	},
	{
		displayName: 'Additional Fields',
		name: 'reportFields',
		type: 'collection',
		placeholder: 'Add Field',
		default: {},
		displayOptions: { show: { ...showForIp, operation: ['report'] } },
		options: [
			{
				displayName: 'Comment',
				name: 'comment',
				type: 'string',
				typeOptions: { rows: 3 },
				default: '',
				description:
					'What happened, for example log lines. Shown publicly, so leave out personal data. Up to 1024 characters.',
			},
			{
				displayName: 'Attack Time',
				name: 'timestamp',
				type: 'dateTime',
				default: '',
				description:
					'When the attack happened. Defaults to now. Times without a time zone are read as UTC.',
			},
		],
	},
];
