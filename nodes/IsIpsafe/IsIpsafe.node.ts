import type {
	IExecuteFunctions,
	ILoadOptionsFunctions,
	INodeExecutionData,
	INodePropertyOptions,
	INodeType,
	INodeTypeDescription,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

import {
	bulkReport,
	checkBlock,
	checkIp,
	clearReports,
	getBlocklist,
	getReports,
	reportIp,
} from './actions';
import { CREDENTIAL_NAME } from './constants';
import { blocklistFields, blocklistOperations } from './descriptions/BlocklistDescription';
import { bulkFields, bulkOperations } from './descriptions/BulkDescription';
import { ipFields, ipOperations } from './descriptions/IpDescription';
import { networkFields, networkOperations } from './descriptions/NetworkDescription';
import { isipsafeApiRequest } from './transport';
import { unwrapData } from './utils';

type ItemOperation = (this: IExecuteFunctions, itemIndex: number) => Promise<INodeExecutionData[]>;

const itemOperations: Record<string, Record<string, ItemOperation>> = {
	ip: { check: checkIp, getReports, report: reportIp, clearReports },
	network: { checkBlock },
	blocklist: { get: getBlocklist },
};

export class IsIpsafe implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'isIPsafe',
		name: 'isIpsafe',
		icon: { light: 'file:../../icons/isipsafe.svg', dark: 'file:../../icons/isipsafe.dark.svg' },
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description:
			'Check IP reputation, report abusive addresses and download the isIPsafe blocklist',
		defaults: {
			name: 'isIPsafe',
		},
		usableAsTool: true,
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: CREDENTIAL_NAME,
				required: false,
			},
		],
		properties: [
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{ name: 'Blocklist', value: 'blocklist' },
					{ name: 'Bulk', value: 'bulk' },
					{ name: 'IP', value: 'ip' },
					{ name: 'Network', value: 'network' },
				],
				default: 'ip',
			},
			{
				displayName:
					'Reporting, bulk reporting, clearing reports and the blocklist need an isIPsafe API key. Lookups work without one (400 per day), or 10,000 per day with a free key.',
				name: 'apiKeyNotice',
				type: 'notice',
				default: '',
			},
			...ipOperations,
			...ipFields,
			...networkOperations,
			...networkFields,
			...blocklistOperations,
			...blocklistFields,
			...bulkOperations,
			...bulkFields,
		],
	};

	methods = {
		loadOptions: {
			async getCategories(this: ILoadOptionsFunctions): Promise<INodePropertyOptions[]> {
				const response = await isipsafeApiRequest.call(this, {
					method: 'GET',
					path: '/categories',
				});
				const categories = unwrapData(response.body);
				if (!Array.isArray(categories)) return [];
				return categories
					.map(
						(category: { slug?: string; name?: string; description?: string; group?: string }) => ({
							name: String(category.name ?? category.slug),
							value: String(category.slug),
							description: [category.group, category.description].filter(Boolean).join(': '),
						}),
					)
					.sort((a, b) => a.name.localeCompare(b.name));
			},
		},
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const resource = this.getNodeParameter('resource', 0) as string;
		const operation = this.getNodeParameter('operation', 0) as string;

		if (resource === 'bulk' && operation === 'report') {
			return [await bulkReport.call(this)];
		}

		const run = itemOperations[resource]?.[operation];
		if (!run) {
			throw new NodeOperationError(
				this.getNode(),
				`The operation "${operation}" is not supported for resource "${resource}"`,
			);
		}

		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				returnData.push(...(await run.call(this, itemIndex)));
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: { error: (error as Error).message },
						pairedItem: { item: itemIndex },
					});
					continue;
				}
				if (error instanceof NodeApiError || error instanceof NodeOperationError) {
					error.context.itemIndex ??= itemIndex;
				}
				if (error instanceof NodeApiError) {
					throw new NodeApiError(this.getNode(), error as unknown as JsonObject);
				}
				throw new NodeOperationError(this.getNode(), error as Error, { itemIndex });
			}
		}
		return [returnData];
	}
}
