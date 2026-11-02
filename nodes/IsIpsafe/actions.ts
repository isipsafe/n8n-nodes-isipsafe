import type { IDataObject, IExecuteFunctions, INodeExecutionData, JsonObject } from 'n8n-workflow';
import { NodeApiError, NodeOperationError } from 'n8n-workflow';

import {
	BLOCKLIST_FILES,
	DEFAULT_MALICIOUS_THRESHOLD,
	MAX_BULK_ROWS,
	MAX_REPORTS_PER_PAGE,
	type BlocklistFormat,
} from './constants';
import { isipsafeApiRequest } from './transport';
import {
	bodyToText,
	buildBulkReportCsv,
	chunk,
	errorDetail,
	formatTimestamp,
	isMalicious,
	normalizeCategories,
	parseCountryList,
	toBulkReportRow,
	truncateComment,
	unwrapData,
	validateIp,
	validateIpOrNetwork,
	validateNetwork,
	type BulkReportRow,
} from './utils';

function asObject(value: unknown): IDataObject {
	return value && typeof value === 'object' && !Array.isArray(value) ? (value as IDataObject) : {};
}

function single(json: IDataObject, itemIndex: number): INodeExecutionData[] {
	return [{ json, pairedItem: { item: itemIndex } }];
}

export async function checkIp(
	this: IExecuteFunctions,
	itemIndex: number,
): Promise<INodeExecutionData[]> {
	const ip = validateIp(this.getNodeParameter('ip', itemIndex));
	const options = this.getNodeParameter('checkOptions', itemIndex, {}) as IDataObject;
	const threshold = Number(options.threshold ?? DEFAULT_MALICIOUS_THRESHOLD);
	const response = await isipsafeApiRequest.call(this, {
		method: 'GET',
		path: '/check',
		qs: {
			ip,
			maxAgeInDays: options.maxAgeInDays as number | undefined,
			verbose: options.verbose === true,
		},
		itemIndex,
	});
	const data = asObject(unwrapData(response.body));
	return single({ ...data, isMalicious: isMalicious(data, threshold) }, itemIndex);
}

export async function getReports(
	this: IExecuteFunctions,
	itemIndex: number,
): Promise<INodeExecutionData[]> {
	const ip = validateIp(this.getNodeParameter('ip', itemIndex));
	const returnAll = this.getNodeParameter('returnAll', itemIndex, false) as boolean;
	const limit = returnAll ? Infinity : (this.getNodeParameter('limit', itemIndex, 50) as number);
	const options = this.getNodeParameter('reportsOptions', itemIndex, {}) as IDataObject;
	const perPage = Math.min(MAX_REPORTS_PER_PAGE, returnAll ? MAX_REPORTS_PER_PAGE : limit);

	const reports: IDataObject[] = [];
	for (let page = 1; reports.length < limit; page++) {
		const response = await isipsafeApiRequest.call(this, {
			method: 'GET',
			path: '/reports',
			qs: { ip, maxAgeInDays: options.maxAgeInDays as number | undefined, page, perPage },
			itemIndex,
		});
		const data = asObject(unwrapData(response.body));
		const results = Array.isArray(data.results) ? (data.results as IDataObject[]) : [];
		reports.push(...results);
		const lastPage = Number(data.lastPage ?? page);
		if (results.length === 0 || !Number.isFinite(lastPage) || page >= lastPage) break;
	}

	return reports
		.slice(0, limit)
		.map((report) => ({ json: { ipAddress: ip, ...report }, pairedItem: { item: itemIndex } }));
}

export async function reportIp(
	this: IExecuteFunctions,
	itemIndex: number,
): Promise<INodeExecutionData[]> {
	const ip = validateIpOrNetwork(this.getNodeParameter('ip', itemIndex));
	const categories = normalizeCategories(this.getNodeParameter('categories', itemIndex));
	const fields = this.getNodeParameter('reportFields', itemIndex, {}) as IDataObject;
	const body: IDataObject = { ip, categories };
	const comment = truncateComment(fields.comment);
	if (comment) body.comment = comment;
	const timestamp = formatTimestamp(fields.timestamp);
	if (timestamp) body.timestamp = timestamp;

	const response = await isipsafeApiRequest.call(this, {
		method: 'POST',
		path: '/report',
		body,
		requireKey: true,
		acceptStatuses: [429],
		itemIndex,
	});
	if (response.statusCode === 429) {
		return single(
			{
				ipAddress: ip,
				duplicate: true,
				message: errorDetail(response.body, 'Already reported in the last 15 minutes'),
			},
			itemIndex,
		);
	}
	return single({ ...asObject(unwrapData(response.body)), duplicate: false }, itemIndex);
}

export async function clearReports(
	this: IExecuteFunctions,
	itemIndex: number,
): Promise<INodeExecutionData[]> {
	const ip = validateIpOrNetwork(this.getNodeParameter('ip', itemIndex));
	const response = await isipsafeApiRequest.call(this, {
		method: 'DELETE',
		path: '/clear-address',
		qs: { ip },
		requireKey: true,
		itemIndex,
	});
	const data = unwrapData(response.body);
	const json: IDataObject =
		data && typeof data === 'object' && !Array.isArray(data)
			? asObject(data)
			: { result: data as string };
	return single({ ipAddress: ip, ...json }, itemIndex);
}

export async function checkBlock(
	this: IExecuteFunctions,
	itemIndex: number,
): Promise<INodeExecutionData[]> {
	const network = validateNetwork(this.getNodeParameter('network', itemIndex));
	const options = this.getNodeParameter('checkBlockOptions', itemIndex, {}) as IDataObject;
	const response = await isipsafeApiRequest.call(this, {
		method: 'GET',
		path: '/check-block',
		qs: { network, maxAgeInDays: options.maxAgeInDays as number | undefined },
		itemIndex,
	});
	return single(asObject(unwrapData(response.body)), itemIndex);
}

export async function getBlocklist(
	this: IExecuteFunctions,
	itemIndex: number,
): Promise<INodeExecutionData[]> {
	const format = this.getNodeParameter('format', itemIndex) as BlocklistFormat;
	const options = this.getNodeParameter('blocklistOptions', itemIndex, {}) as IDataObject;
	const qs: IDataObject = {
		format,
		confidenceMinimum: options.confidenceMinimum as number | undefined,
		limit: options.addressLimit as number | undefined,
		days: options.days as number | undefined,
		ipVersion:
			options.ipVersion === '4' || options.ipVersion === '6' ? options.ipVersion : undefined,
		onlyCountries: parseCountryList(options.onlyCountries),
		exceptCountries: parseCountryList(options.exceptCountries),
	};

	if (format === 'json') {
		const response = await isipsafeApiRequest.call(this, {
			method: 'GET',
			path: '/blocklist',
			qs,
			requireKey: true,
			itemIndex,
		});
		return blocklistEntries(unwrapData(response.body)).map((entry) => ({
			json: entry,
			pairedItem: { item: itemIndex },
		}));
	}

	const response = await isipsafeApiRequest.call(this, {
		method: 'GET',
		path: '/blocklist',
		qs,
		requireKey: true,
		expectText: true,
		itemIndex,
	});
	const text = bodyToText(response.body);
	const output = this.getNodeParameter('output', itemIndex, 'text') as string;
	if (output !== 'binary') {
		return single({ format, blocklist: text }, itemIndex);
	}
	const file = BLOCKLIST_FILES[format];
	const binaryPropertyName = this.getNodeParameter(
		'binaryPropertyName',
		itemIndex,
		'data',
	) as string;
	const binary = await this.helpers.prepareBinaryData(
		Buffer.from(text, 'utf8'),
		`isipsafe-blocklist-${format}.${file.extension}`,
		file.mimeType,
	);
	return [
		{ json: { format }, binary: { [binaryPropertyName]: binary }, pairedItem: { item: itemIndex } },
	];
}

export function blocklistEntries(data: unknown): IDataObject[] {
	let list: unknown = data;
	if (!Array.isArray(list)) {
		const container = asObject(list);
		list = container.ips ?? container.addresses ?? container.results ?? [];
	}
	if (!Array.isArray(list)) return [];
	return list.map((entry) => (typeof entry === 'string' ? { ipAddress: entry } : asObject(entry)));
}

/**
 * Turns every input item into a CSV row and uploads the rows in batches of up to 10,000.
 * Returns one output item per upload, paired with the input items it contains.
 */
export async function bulkReport(this: IExecuteFunctions): Promise<INodeExecutionData[]> {
	const items = this.getInputData();
	const rows: Array<{ row: BulkReportRow; itemIndex: number }> = [];
	const skipped: IDataObject[] = [];

	for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
		try {
			const row = toBulkReportRow({
				ip: this.getNodeParameter('ip', itemIndex),
				categories: this.getNodeParameter('categories', itemIndex),
				timestamp: this.getNodeParameter('timestamp', itemIndex, ''),
				comment: this.getNodeParameter('comment', itemIndex, ''),
			});
			rows.push({ row, itemIndex });
		} catch (error) {
			if (!this.continueOnFail()) {
				throw new NodeOperationError(this.getNode(), error as Error, { itemIndex });
			}
			skipped.push({ itemIndex, error: (error as Error).message });
		}
	}

	if (rows.length === 0) {
		const message = 'No valid rows to report';
		if (!this.continueOnFail()) throw new NodeOperationError(this.getNode(), message);
		return [
			{
				json: { error: message, skippedItems: skipped },
				pairedItem: items.map((_, item) => ({ item })),
			},
		];
	}

	const output: INodeExecutionData[] = [];
	const batches = chunk(rows, MAX_BULK_ROWS);
	for (const [batchIndex, batch] of batches.entries()) {
		const pairedItem = batch.map(({ itemIndex }) => ({ item: itemIndex }));
		const meta: IDataObject = {
			batch: batchIndex + 1,
			batches: batches.length,
			rows: batch.length,
		};
		if (batchIndex === 0 && skipped.length) meta.skippedItems = skipped;
		try {
			const response = await isipsafeApiRequest.call(this, {
				method: 'POST',
				path: '/bulk-report',
				body: buildBulkReportCsv(batch.map(({ row }) => row)),
				contentType: 'text/csv',
				requireKey: true,
				retry: false,
				itemIndex: batch[0].itemIndex,
			});
			output.push({ json: { ...asObject(unwrapData(response.body)), ...meta }, pairedItem });
		} catch (error) {
			if (!this.continueOnFail()) {
				if (error instanceof NodeOperationError)
					throw new NodeOperationError(this.getNode(), error);
				throw new NodeApiError(this.getNode(), error as JsonObject);
			}
			output.push({ json: { error: (error as Error).message, ...meta }, pairedItem });
		}
	}
	return output;
}
