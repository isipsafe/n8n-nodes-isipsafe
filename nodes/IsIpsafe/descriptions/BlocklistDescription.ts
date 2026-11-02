import type { INodeProperties } from 'n8n-workflow';

const showForBlocklist = { resource: ['blocklist'], operation: ['get'] };

export const blocklistOperations: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['blocklist'] } },
		options: [
			{
				name: 'Get',
				value: 'get',
				description: 'Download the highest-confidence abusive addresses',
				action: 'Get the blocklist',
			},
		],
		default: 'get',
	},
];

export const blocklistFields: INodeProperties[] = [
	{
		displayName: 'Format',
		name: 'format',
		type: 'options',
		options: [
			{ name: 'Apache', value: 'apache', description: 'Apache "Require not ip" rules' },
			{ name: 'CSV', value: 'csv' },
			{ name: 'Ipset', value: 'ipset', description: 'Linux ipset restore file' },
			{ name: 'JSON', value: 'json', description: 'One output item per address' },
			{ name: 'MikroTik', value: 'mikrotik', description: 'RouterOS address-list script' },
			{ name: 'Nftables', value: 'nftables', description: 'Linux nftables set' },
			{ name: 'Nginx', value: 'nginx', description: 'Nginx deny rules' },
			{ name: 'Plain Text', value: 'txt', description: 'One address per line' },
			{ name: 'STIX', value: 'stix', description: 'STIX 2.1 bundle' },
		],
		default: 'json',
		description: 'Format of the blocklist',
		displayOptions: { show: showForBlocklist },
	},
	{
		displayName: 'Put Output In',
		name: 'output',
		type: 'options',
		options: [
			{
				name: 'Text Field',
				value: 'text',
				description: 'Return the blocklist in the "blocklist" field',
			},
			{ name: 'Binary File', value: 'binary', description: 'Return the blocklist as a file' },
		],
		default: 'text',
		displayOptions: { show: showForBlocklist, hide: { format: ['json'] } },
	},
	{
		displayName: 'Put Output File in Field',
		name: 'binaryPropertyName',
		type: 'string',
		default: 'data',
		required: true,
		hint: 'The name of the output binary field to put the file in',
		displayOptions: {
			show: { ...showForBlocklist, output: ['binary'] },
			hide: { format: ['json'] },
		},
	},
	{
		displayName: 'Options',
		name: 'blocklistOptions',
		type: 'collection',
		placeholder: 'Add Option',
		default: {},
		displayOptions: { show: showForBlocklist },
		options: [
			{
				displayName: 'Confidence Minimum',
				name: 'confidenceMinimum',
				type: 'number',
				typeOptions: { minValue: 1, maxValue: 100 },
				default: 75,
				description: 'Only include addresses with at least this abuse confidence score',
			},
			{
				displayName: 'Except Countries',
				name: 'exceptCountries',
				type: 'string',
				default: '',
				placeholder: 'e.g. GB,IE',
				description: 'Comma-separated two-letter country codes to leave out',
			},
			{
				displayName: 'IP Version',
				name: 'ipVersion',
				type: 'options',
				options: [
					{ name: 'Both', value: 'both' },
					{ name: 'IPv4 Only', value: '4' },
					{ name: 'IPv6 Only', value: '6' },
				],
				default: 'both',
			},
			{
				displayName: 'Max Addresses',
				name: 'addressLimit',
				type: 'number',
				typeOptions: { minValue: 1, maxValue: 500000 },
				default: 10000,
				description: 'Maximum number of addresses in the list',
			},
			{
				displayName: 'Max Age (Days)',
				name: 'days',
				type: 'number',
				typeOptions: { minValue: 1, maxValue: 90 },
				default: 30,
				description: 'Only include addresses reported in the last this many days',
			},
			{
				displayName: 'Only Countries',
				name: 'onlyCountries',
				type: 'string',
				default: '',
				placeholder: 'e.g. CN,RU',
				description: 'Comma-separated two-letter country codes to limit the list to',
			},
		],
	},
];
