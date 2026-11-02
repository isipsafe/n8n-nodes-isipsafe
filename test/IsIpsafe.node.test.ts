import { NodeApiError, NodeOperationError } from 'n8n-workflow';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { IsIpsafeApi } from '../credentials/IsIpsafeApi.credentials';
import { PACKAGE_VERSION, USER_AGENT } from '../nodes/IsIpsafe/constants';
import { IsIpsafe } from '../nodes/IsIpsafe/IsIpsafe.node';
import packageJson from '../package.json';
import { createContext } from './context';

const { sleep } = vi.hoisted(() => ({ sleep: vi.fn(async () => undefined) }));
vi.mock('n8n-workflow', async (importOriginal) => ({
	...(await importOriginal<typeof import('n8n-workflow')>()),
	sleep,
}));

const node = new IsIpsafe();

const checkData = {
	ipAddress: '185.220.101.1',
	isWhitelisted: false,
	abuseConfidenceScore: 88,
	totalReports: 24,
	confidenceBand: 'High',
};

beforeEach(() => sleep.mockClear());

describe('node description', () => {
	it('is usable as an AI tool and declares an optional credential', () => {
		expect(node.description.usableAsTool).toBe(true);
		expect(node.description.credentials).toEqual([{ name: 'isIpsafeApi', required: false }]);
	});

	it('keeps the User-Agent version in sync with package.json', () => {
		expect(PACKAGE_VERSION).toBe(packageJson.version);
		expect(USER_AGENT).toBe(`isipsafe-n8n/${packageJson.version}`);
	});

	it('registers the built node and credential in package.json', () => {
		expect(packageJson.n8n.nodes).toEqual(['dist/nodes/IsIpsafe/IsIpsafe.node.js']);
		expect(packageJson.n8n.credentials).toEqual(['dist/credentials/IsIpsafeApi.credentials.js']);
		expect(packageJson).not.toHaveProperty('dependencies');
	});
});

describe('credentials', () => {
	const credential = new IsIpsafeApi();

	it('sends the key as a Bearer header', () => {
		expect(credential.authenticate).toEqual({
			type: 'generic',
			properties: { headers: { Authorization: '=Bearer {{$credentials.apiKey}}' } },
		});
		expect(credential.properties[0].typeOptions?.password).toBe(true);
	});

	it('tests the key with a GET lookup', () => {
		expect(credential.test.request).toMatchObject({
			baseURL: 'https://isipsafe.com/api/v1',
			url: '/check',
			method: 'GET',
		});
	});
});

describe('IP > Check', () => {
	it('works without a credential and adds isMalicious', async () => {
		const fake = createContext({
			params: {
				resource: 'ip',
				operation: 'check',
				ip: '185.220.101.1',
				checkOptions: { maxAgeInDays: 90 },
			},
			responses: [{ body: { data: checkData } }],
		});
		const [output] = await node.execute.call(fake.context);

		expect(output).toEqual([
			{ json: { ...checkData, isMalicious: true }, pairedItem: { item: 0 } },
		]);
		expect(fake.httpRequestWithAuthentication).not.toHaveBeenCalled();
		const [request] = fake.requests();
		expect(request).toMatchObject({
			method: 'GET',
			url: 'https://isipsafe.com/api/v1/check',
			qs: { ip: '185.220.101.1', maxAgeInDays: 90 },
			timeout: 10000,
			returnFullResponse: true,
			ignoreHttpStatusErrors: true,
		});
		expect(request.headers).toMatchObject({ 'User-Agent': USER_AGENT, Accept: 'application/json' });
		expect(request.headers).not.toHaveProperty('Authorization');
	});

	it('uses the credential when one is selected', async () => {
		const fake = createContext({
			params: {
				resource: 'ip',
				operation: 'check',
				ip: '185.220.101.1',
				checkOptions: { verbose: true },
			},
			apiKey: 'sl_test',
			responses: [{ body: { data: checkData } }],
		});
		await node.execute.call(fake.context);

		expect(fake.httpRequest).not.toHaveBeenCalled();
		expect(fake.httpRequestWithAuthentication).toHaveBeenCalledWith(
			'isIpsafeApi',
			expect.anything(),
		);
		expect(fake.requests()[0].qs).toEqual({ ip: '185.220.101.1', verbose: 'true' });
	});

	it('does not flag allowlisted addresses', async () => {
		const allowlisted = {
			ipAddress: '8.8.8.8',
			isWhitelisted: true,
			abuseConfidenceScore: 100,
			totalReports: 0,
		};
		const fake = createContext({
			params: { resource: 'ip', operation: 'check', ip: '8.8.8.8', checkOptions: {} },
			responses: [{ body: { data: allowlisted } }],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output[0].json.isMalicious).toBe(false);
	});

	it('applies a custom threshold per item and keeps item pairing', async () => {
		const fake = createContext({
			items: [{ json: {} }, { json: {} }],
			params: (itemIndex) => ({
				resource: 'ip',
				operation: 'check',
				ip: itemIndex === 0 ? '185.220.101.1' : '185.220.101.2',
				checkOptions: { threshold: 95 },
			}),
			responses: [
				{ body: { data: checkData } },
				{ body: { data: { ...checkData, abuseConfidenceScore: 99 } } },
			],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output.map((item) => [item.json.isMalicious, item.pairedItem])).toEqual([
			[false, { item: 0 }],
			[true, { item: 1 }],
		]);
	});

	it('rejects an invalid IP before calling the API', async () => {
		const fake = createContext({
			params: { resource: 'ip', operation: 'check', ip: 'not-an-ip', checkOptions: {} },
		});
		const error = await node.execute.call(fake.context).catch((caught: unknown) => caught);
		expect(error).toBeInstanceOf(NodeOperationError);
		expect((error as NodeOperationError).message).toContain('Not a valid IPv4 or IPv6 address');
		expect((error as NodeOperationError).context.itemIndex).toBe(0);
		expect(fake.requests()).toHaveLength(0);
	});

	it('returns an error item per failed input when Continue On Fail is on', async () => {
		const fake = createContext({
			items: [{ json: {} }, { json: {} }],
			params: (itemIndex) => ({
				resource: 'ip',
				operation: 'check',
				ip: itemIndex === 0 ? 'bad' : '185.220.101.1',
				checkOptions: {},
			}),
			continueOnFail: true,
			responses: [{ body: { data: checkData } }],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output[0]).toEqual({
			json: { error: 'Not a valid IPv4 or IPv6 address: "bad"' },
			pairedItem: { item: 0 },
		});
		expect(output[1].pairedItem).toEqual({ item: 1 });
		expect(output[1].json.isMalicious).toBe(true);
	});

	it('retries lookups on 5xx and network errors', async () => {
		const fake = createContext({
			params: { resource: 'ip', operation: 'check', ip: '185.220.101.1', checkOptions: {} },
			responses: [
				{ statusCode: 503, body: '' },
				{ networkError: true },
				{ body: { data: checkData } },
			],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output[0].json.ipAddress).toBe('185.220.101.1');
		expect(fake.requests()).toHaveLength(3);
		expect(sleep).toHaveBeenCalledTimes(2);
	});

	it('gives up after two retries', async () => {
		const fake = createContext({
			params: { resource: 'ip', operation: 'check', ip: '185.220.101.1', checkOptions: {} },
			responses: [{ networkError: true }, { networkError: true }, { networkError: true }],
		});
		const error = await node.execute.call(fake.context).catch((caught: unknown) => caught);
		expect(error).toBeInstanceOf(NodeApiError);
		expect((error as NodeApiError).messages).toContain('Could not reach the isIPsafe API');
		expect(fake.requests()).toHaveLength(3);
	});

	it('surfaces the API error detail and status', async () => {
		const fake = createContext({
			params: { resource: 'ip', operation: 'check', ip: '185.220.101.1', checkOptions: {} },
			apiKey: 'sl_wrong',
			responses: [
				{ statusCode: 401, body: { errors: [{ detail: 'Invalid API key', status: 401 }] } },
			],
		});
		const error = await node.execute.call(fake.context).catch((caught: unknown) => caught);
		expect(error).toBeInstanceOf(NodeApiError);
		expect((error as NodeApiError).message).toBe('Invalid API key');
		expect((error as NodeApiError).httpCode).toBe('401');
		expect((error as NodeApiError).context.itemIndex).toBe(0);
		expect(fake.requests()).toHaveLength(1);
	});
});

describe('IP > Get Reports', () => {
	const page = (pageNumber: number, lastPage: number, count: number) => ({
		body: {
			data: {
				ipAddress: '185.220.101.1',
				page: pageNumber,
				lastPage,
				results: Array.from({ length: count }, (_, index) => ({
					reportedAt: `p${pageNumber}-${index}`,
				})),
			},
		},
	});

	it('follows every page when Return All is on', async () => {
		const fake = createContext({
			params: {
				resource: 'ip',
				operation: 'getReports',
				ip: '185.220.101.1',
				returnAll: true,
				reportsOptions: {},
			},
			responses: [page(1, 2, 100), page(2, 2, 3)],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output).toHaveLength(103);
		expect(output[0]).toEqual({
			json: { ipAddress: '185.220.101.1', reportedAt: 'p1-0' },
			pairedItem: { item: 0 },
		});
		expect(fake.requests().map((request) => request.qs)).toEqual([
			{ ip: '185.220.101.1', page: 1, perPage: 100 },
			{ ip: '185.220.101.1', page: 2, perPage: 100 },
		]);
	});

	it('stops at the limit', async () => {
		const fake = createContext({
			params: {
				resource: 'ip',
				operation: 'getReports',
				ip: '185.220.101.1',
				returnAll: false,
				limit: 3,
				reportsOptions: { maxAgeInDays: 7 },
			},
			responses: [page(1, 5, 3)],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output).toHaveLength(3);
		expect(fake.requests()[0].qs).toEqual({
			ip: '185.220.101.1',
			maxAgeInDays: 7,
			page: 1,
			perPage: 3,
		});
	});
});

describe('IP > Report', () => {
	const reportParams = {
		resource: 'ip',
		operation: 'report',
		ip: '203.0.113.50',
		categories: ['ssh', 'brute-force'],
		reportFields: { comment: 'sshd: 212 failed logins', timestamp: '2026-11-02T10:00:00' },
	};

	it('needs an API key', async () => {
		const fake = createContext({ params: reportParams });
		const error = await node.execute.call(fake.context).catch((caught: unknown) => caught);
		expect(error).toBeInstanceOf(NodeOperationError);
		expect((error as Error).message).toBe('This operation needs an isIPsafe API key');
		expect(fake.requests()).toHaveLength(0);
	});

	it('posts the report as JSON', async () => {
		const fake = createContext({
			params: reportParams,
			apiKey: 'sl_test',
			responses: [
				{
					body: {
						data: {
							ipAddress: '203.0.113.50',
							abuseConfidenceScore: 40,
							link: 'https://isipsafe.com/ip/203.0.113.50',
						},
					},
				},
			],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output[0].json).toEqual({
			ipAddress: '203.0.113.50',
			abuseConfidenceScore: 40,
			link: 'https://isipsafe.com/ip/203.0.113.50',
			duplicate: false,
		});
		expect(fake.requests()[0]).toMatchObject({
			method: 'POST',
			url: 'https://isipsafe.com/api/v1/report',
			json: true,
			body: {
				ip: '203.0.113.50',
				categories: ['ssh', 'brute-force'],
				comment: 'sshd: 212 failed logins',
				timestamp: '2026-11-02T10:00:00.000Z',
			},
		});
	});

	it('treats 429 as a duplicate instead of an error and does not retry', async () => {
		const fake = createContext({
			params: { ...reportParams, reportFields: {} },
			apiKey: 'sl_test',
			responses: [
				{
					statusCode: 429,
					body: {
						errors: [
							{ detail: 'You can only report the same IP once every 15 minutes', status: 429 },
						],
					},
				},
			],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output).toEqual([
			{
				json: {
					ipAddress: '203.0.113.50',
					duplicate: true,
					message: 'You can only report the same IP once every 15 minutes',
				},
				pairedItem: { item: 0 },
			},
		]);
		expect(fake.requests()).toHaveLength(1);
		expect(fake.requests()[0].body).toEqual({
			ip: '203.0.113.50',
			categories: ['ssh', 'brute-force'],
		});
	});

	it('does not retry reports on 5xx', async () => {
		const fake = createContext({
			params: reportParams,
			apiKey: 'sl_test',
			responses: [{ statusCode: 502, body: '' }],
		});
		await expect(node.execute.call(fake.context)).rejects.toBeInstanceOf(NodeApiError);
		expect(fake.requests()).toHaveLength(1);
	});
});

describe('IP > Clear Reports', () => {
	it('sends a DELETE with the address', async () => {
		const fake = createContext({
			params: { resource: 'ip', operation: 'clearReports', ip: '203.0.113.50' },
			apiKey: 'sl_test',
			responses: [{ body: { data: { numReportsDeleted: 2 } } }],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output[0].json).toEqual({ ipAddress: '203.0.113.50', numReportsDeleted: 2 });
		expect(fake.requests()[0]).toMatchObject({
			method: 'DELETE',
			url: 'https://isipsafe.com/api/v1/clear-address',
			qs: { ip: '203.0.113.50' },
		});
	});
});

describe('Network > Check Block', () => {
	it('validates the network and returns the block summary', async () => {
		const data = { networkAddress: '185.220.101.0', netmask: '255.255.255.0', reportedAddress: [] };
		const fake = createContext({
			params: {
				resource: 'network',
				operation: 'checkBlock',
				network: '185.220.101.0/24',
				checkBlockOptions: {},
			},
			responses: [{ body: { data } }],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output).toEqual([{ json: data, pairedItem: { item: 0 } }]);
		expect(fake.requests()[0].qs).toEqual({ network: '185.220.101.0/24' });
	});
});

describe('Blocklist > Get', () => {
	it('returns one item per address for JSON', async () => {
		const fake = createContext({
			params: {
				resource: 'blocklist',
				operation: 'get',
				format: 'json',
				blocklistOptions: {
					confidenceMinimum: 90,
					ipVersion: '4',
					exceptCountries: 'gb, ie',
					addressLimit: 2,
				},
			},
			apiKey: 'sl_test',
			responses: [
				{
					body: {
						meta: {},
						data: [{ ipAddress: '1.2.3.4', abuseConfidenceScore: 100 }, '5.6.7.8'],
					},
				},
			],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output).toEqual([
			{ json: { ipAddress: '1.2.3.4', abuseConfidenceScore: 100 }, pairedItem: { item: 0 } },
			{ json: { ipAddress: '5.6.7.8' }, pairedItem: { item: 0 } },
		]);
		expect(fake.requests()[0].qs).toEqual({
			format: 'json',
			confidenceMinimum: 90,
			limit: 2,
			ipVersion: '4',
			exceptCountries: 'GB,IE',
		});
	});

	it('returns other formats as text', async () => {
		const fake = createContext({
			params: {
				resource: 'blocklist',
				operation: 'get',
				format: 'txt',
				output: 'text',
				blocklistOptions: {},
			},
			apiKey: 'sl_test',
			responses: [{ body: '1.2.3.4\n5.6.7.8\n' }],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output).toEqual([
			{ json: { format: 'txt', blocklist: '1.2.3.4\n5.6.7.8\n' }, pairedItem: { item: 0 } },
		]);
		expect(fake.requests()[0]).toMatchObject({ encoding: 'text', json: false });
	});

	it('returns other formats as a binary file', async () => {
		const fake = createContext({
			params: {
				resource: 'blocklist',
				operation: 'get',
				format: 'nftables',
				output: 'binary',
				binaryPropertyName: 'blocklist',
				blocklistOptions: {},
			},
			apiKey: 'sl_test',
			responses: [{ body: 'add element inet filter isipsafe { 1.2.3.4 }\n' }],
		});
		const [output] = await node.execute.call(fake.context);
		expect(fake.prepareBinaryData).toHaveBeenCalledWith(
			Buffer.from('add element inet filter isipsafe { 1.2.3.4 }\n'),
			'isipsafe-blocklist-nftables.nft',
			'text/plain',
		);
		expect(output[0].json).toEqual({ format: 'nftables' });
		expect(output[0].binary?.blocklist).toMatchObject({
			fileName: 'isipsafe-blocklist-nftables.nft',
		});
		expect(output[0].pairedItem).toEqual({ item: 0 });
	});

	it('needs an API key', async () => {
		const fake = createContext({
			params: { resource: 'blocklist', operation: 'get', format: 'json', blocklistOptions: {} },
		});
		await expect(node.execute.call(fake.context)).rejects.toThrow(
			'This operation needs an isIPsafe API key',
		);
	});
});

describe('Bulk > Report', () => {
	const rows = [
		{ ip: '203.0.113.50', categories: 'ssh,brute-force', comment: 'sshd' },
		{ ip: '198.51.100.4', categories: ['port-scan'], comment: '' },
		{ ip: 'garbage', categories: 'ssh', comment: '' },
	];
	const bulkParams = (itemIndex: number) => ({
		resource: 'bulk',
		operation: 'report',
		timestamp: '',
		...rows[itemIndex],
	});

	it('uploads every item as one CSV and pairs the result with all inputs', async () => {
		const fake = createContext({
			items: rows.slice(0, 2).map((json) => ({ json })),
			params: bulkParams,
			apiKey: 'sl_test',
			responses: [{ body: { data: { savedReports: 2, invalidReports: [] } } }],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output).toEqual([
			{
				json: { savedReports: 2, invalidReports: [], batch: 1, batches: 1, rows: 2 },
				pairedItem: [{ item: 0 }, { item: 1 }],
			},
		]);
		const [request] = fake.requests();
		expect(request).toMatchObject({
			method: 'POST',
			url: 'https://isipsafe.com/api/v1/bulk-report',
			json: false,
			body: 'IP,Categories,ReportDate,Comment\n203.0.113.50,"ssh,brute-force",,sshd\n198.51.100.4,port-scan,,\n',
		});
		expect(request.headers).toMatchObject({ 'Content-Type': 'text/csv' });
	});

	it('fails on an invalid row by default', async () => {
		const fake = createContext({
			items: rows.map((json) => ({ json })),
			params: bulkParams,
			apiKey: 'sl_test',
		});
		const error = await node.execute.call(fake.context).catch((caught: unknown) => caught);
		expect(error).toBeInstanceOf(NodeOperationError);
		expect((error as NodeOperationError).context.itemIndex).toBe(2);
		expect(fake.requests()).toHaveLength(0);
	});

	it('skips invalid rows with Continue On Fail', async () => {
		const fake = createContext({
			items: rows.map((json) => ({ json })),
			params: bulkParams,
			apiKey: 'sl_test',
			continueOnFail: true,
			responses: [{ body: { data: { savedReports: 2, invalidReports: [] } } }],
		});
		const [output] = await node.execute.call(fake.context);
		expect(output[0].json.skippedItems).toEqual([
			{ itemIndex: 2, error: 'Not a valid IP address or CIDR network: "garbage"' },
		]);
		expect(output[0].pairedItem).toEqual([{ item: 0 }, { item: 1 }]);
	});

	it('does not retry the upload', async () => {
		const fake = createContext({
			items: rows.slice(0, 1).map((json) => ({ json })),
			params: bulkParams,
			apiKey: 'sl_test',
			responses: [{ statusCode: 503, body: '' }],
		});
		await expect(node.execute.call(fake.context)).rejects.toBeInstanceOf(NodeApiError);
		expect(fake.requests()).toHaveLength(1);
	});
});

describe('loadOptions', () => {
	it('lists categories by name with their slug as value', async () => {
		const fake = createContext({
			params: {},
			responses: [
				{
					body: {
						data: [
							{ id: 22, slug: 'ssh', name: 'SSH', group: 'Network', description: 'SSH abuse' },
							{
								id: 18,
								slug: 'brute-force',
								name: 'Brute-Force',
								group: 'Access',
								description: 'Guessing',
							},
						],
					},
				},
			],
		});
		const options = await node.methods.loadOptions.getCategories.call(fake.context);
		expect(options).toEqual([
			{ name: 'Brute-Force', value: 'brute-force', description: 'Access: Guessing' },
			{ name: 'SSH', value: 'ssh', description: 'Network: SSH abuse' },
		]);
		expect(fake.requests()[0].url).toBe('https://isipsafe.com/api/v1/categories');
	});
});
