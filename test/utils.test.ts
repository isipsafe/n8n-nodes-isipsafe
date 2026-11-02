import { describe, expect, it } from 'vitest';

import {
	backoffDelayMs,
	buildBulkReportCsv,
	chunk,
	errorDetail,
	formatTimestamp,
	isIPv4,
	isIPv6,
	isMalicious,
	isValidNetwork,
	normalizeCategories,
	parseBody,
	parseCountryList,
	toBulkReportRow,
	truncateComment,
	unwrapData,
	validateIp,
	validateIpOrNetwork,
	validateNetwork,
} from '../nodes/IsIpsafe/utils';

describe('isMalicious', () => {
	it('flags a reported address at or above the threshold', () => {
		expect(isMalicious({ isWhitelisted: false, totalReports: 3, abuseConfidenceScore: 75 })).toBe(
			true,
		);
		expect(isMalicious({ isWhitelisted: false, totalReports: 3, abuseConfidenceScore: 74 })).toBe(
			false,
		);
	});

	it('never flags allowlisted addresses, even with a score of 100', () => {
		expect(isMalicious({ isWhitelisted: true, totalReports: 0, abuseConfidenceScore: 100 })).toBe(
			false,
		);
		expect(isMalicious({ isWhitelisted: true, totalReports: 12, abuseConfidenceScore: 100 })).toBe(
			false,
		);
	});

	it('never flags addresses without reports', () => {
		expect(isMalicious({ isWhitelisted: false, totalReports: 0, abuseConfidenceScore: 100 })).toBe(
			false,
		);
		expect(isMalicious({ abuseConfidenceScore: 100 })).toBe(false);
	});

	it('uses a custom threshold', () => {
		const result = { isWhitelisted: false, totalReports: 1, abuseConfidenceScore: 56 };
		expect(isMalicious(result, 50)).toBe(true);
		expect(isMalicious(result, 90)).toBe(false);
	});

	it('ignores missing or non-numeric scores', () => {
		expect(isMalicious({ totalReports: 4 })).toBe(false);
		expect(isMalicious({ totalReports: 4, abuseConfidenceScore: 'high' })).toBe(false);
	});
});

describe('IP validation', () => {
	it.each(['1.2.3.4', '0.0.0.0', '255.255.255.255', '185.220.101.1'])('accepts IPv4 %s', (ip) => {
		expect(isIPv4(ip)).toBe(true);
		expect(validateIp(` ${ip} `)).toBe(ip);
	});

	it.each(['256.1.1.1', '1.2.3', '1.2.3.4.5', '01.2.3.4', 'a.b.c.d', '', '1.2.3.4/32'])(
		'rejects IPv4 %s',
		(ip) => expect(isIPv4(ip)).toBe(false),
	);

	it.each([
		'::',
		'::1',
		'2001:db8::1',
		'2001:0db8:0000:0000:0000:ff00:0042:8329',
		'fe80::1:2:3:4',
		'::ffff:192.0.2.1',
		'2001:db8:1:2:3:4:5::',
	])('accepts IPv6 %s', (ip) => {
		expect(isIPv6(ip)).toBe(true);
		expect(validateIp(ip)).toBe(ip);
	});

	it.each([
		'2001:db8::1::2',
		'2001:db8:1:2:3:4:5:6:7',
		'2001:db8:1:2:3:4:5',
		'12345::',
		':1::',
		'gggg::1',
		'::ffff:300.0.2.1',
		'fe80::1%eth0',
	])('rejects IPv6 %s', (ip) => expect(isIPv6(ip)).toBe(false));

	it('throws a readable error for invalid input', () => {
		expect(() => validateIp('example.com')).toThrow(
			'Not a valid IPv4 or IPv6 address: "example.com"',
		);
		expect(() => validateIp(undefined)).toThrow('Not a valid IPv4 or IPv6 address');
	});

	it('validates networks', () => {
		expect(isValidNetwork('185.220.101.0/24')).toBe(true);
		expect(isValidNetwork('2001:db8::/48')).toBe(true);
		expect(isValidNetwork('10.0.0.0/33')).toBe(false);
		expect(isValidNetwork('2001:db8::/129')).toBe(false);
		expect(isValidNetwork('10.0.0.0')).toBe(false);
		expect(isValidNetwork('10.0.0.0/x')).toBe(false);
		expect(validateNetwork(' 185.220.101.0/24 ')).toBe('185.220.101.0/24');
		expect(() => validateNetwork('185.220.101.1')).toThrow('Not a valid CIDR network');
	});

	it('accepts an address or a network for reports', () => {
		expect(validateIpOrNetwork('203.0.113.50')).toBe('203.0.113.50');
		expect(validateIpOrNetwork('203.0.113.0/24')).toBe('203.0.113.0/24');
		expect(() => validateIpOrNetwork('203.0.113.0/40')).toThrow(
			'Not a valid IP address or CIDR network',
		);
	});
});

describe('normalizeCategories', () => {
	it('splits strings, trims and removes duplicates', () => {
		expect(normalizeCategories(' ssh, brute-force,ssh ,, ')).toEqual(['ssh', 'brute-force']);
	});

	it('accepts arrays of slugs and numeric IDs', () => {
		expect(normalizeCategories(['ssh', 18, 'port-scan,ssh'])).toEqual(['ssh', '18', 'port-scan']);
		expect(normalizeCategories(22)).toEqual(['22']);
	});

	it('requires between 1 and 12 categories', () => {
		expect(() => normalizeCategories('')).toThrow('At least one category is required');
		expect(() => normalizeCategories(undefined)).toThrow('At least one category is required');
		const thirteen = Array.from({ length: 13 }, (_, index) => String(index + 1));
		expect(() => normalizeCategories(thirteen)).toThrow('At most 12 categories');
	});
});

describe('formatTimestamp', () => {
	it('returns undefined for empty values', () => {
		expect(formatTimestamp(undefined)).toBeUndefined();
		expect(formatTimestamp('')).toBeUndefined();
		expect(formatTimestamp('  ')).toBeUndefined();
	});

	it('keeps strings that carry a time zone', () => {
		expect(formatTimestamp('2026-11-02T10:00:00+05:30')).toBe('2026-11-02T10:00:00+05:30');
		expect(formatTimestamp('2026-11-02T10:00:00Z')).toBe('2026-11-02T10:00:00Z');
	});

	it('reads times without a zone as UTC', () => {
		expect(formatTimestamp('2026-11-02T10:00:00')).toBe('2026-11-02T10:00:00.000Z');
		expect(formatTimestamp('2026-11-02 10:00:00')).toBe('2026-11-02T10:00:00.000Z');
		expect(formatTimestamp('2026-11-02')).toBe('2026-11-02T00:00:00.000Z');
	});

	it('accepts Date and Luxon-like objects', () => {
		expect(formatTimestamp(new Date(Date.UTC(2026, 10, 2, 8)))).toBe('2026-11-02T08:00:00.000Z');
		expect(formatTimestamp({ toISO: () => '2026-11-02T08:00:00.000+01:00' })).toBe(
			'2026-11-02T08:00:00.000+01:00',
		);
	});

	it('rejects invalid dates', () => {
		expect(() => formatTimestamp('yesterday')).toThrow('Invalid report date');
		expect(() => formatTimestamp(new Date('nope'))).toThrow('Invalid report date');
	});
});

describe('bulk CSV', () => {
	it('builds the header and rows, escaping commas, quotes and new lines', () => {
		const csv = buildBulkReportCsv([
			toBulkReportRow({
				ip: '203.0.113.50',
				categories: 'ssh,brute-force',
				comment: 'sshd: "root" login',
			}),
			toBulkReportRow({
				ip: '2001:db8::1',
				categories: ['port-scan'],
				timestamp: '2026-11-02T10:00:00Z',
				comment: 'line one\nline two',
			}),
			toBulkReportRow({ ip: '198.51.100.0/24', categories: 14 }),
		]);
		expect(csv).toBe(
			[
				'IP,Categories,ReportDate,Comment',
				'203.0.113.50,"ssh,brute-force",,"sshd: ""root"" login"',
				'2001:db8::1,port-scan,2026-11-02T10:00:00Z,"line one\nline two"',
				'198.51.100.0/24,14,,',
				'',
			].join('\n'),
		);
	});

	it('validates each row', () => {
		expect(() => toBulkReportRow({ ip: 'nope', categories: 'ssh' })).toThrow(
			'Not a valid IP address',
		);
		expect(() => toBulkReportRow({ ip: '203.0.113.50', categories: '' })).toThrow(
			'At least one category',
		);
	});

	it('truncates comments to 1024 characters', () => {
		expect(truncateComment('x'.repeat(2000))).toHaveLength(1024);
		expect(truncateComment(undefined)).toBe('');
	});

	it('splits rows into batches', () => {
		expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
		expect(chunk([], 2)).toEqual([]);
	});
});

describe('response helpers', () => {
	it('parses JSON bodies from strings and buffers', () => {
		expect(parseBody('{"data":{"a":1}}')).toEqual({ data: { a: 1 } });
		expect(parseBody(Buffer.from('{"data":[1]}'))).toEqual({ data: [1] });
		expect(parseBody('1.2.3.4\n5.6.7.8')).toBe('1.2.3.4\n5.6.7.8');
		expect(parseBody({ data: 1 })).toEqual({ data: 1 });
		expect(parseBody('')).toBeUndefined();
	});

	it('unwraps the data envelope', () => {
		expect(unwrapData({ data: { ipAddress: '1.2.3.4' } })).toEqual({ ipAddress: '1.2.3.4' });
		expect(unwrapData([1, 2])).toEqual([1, 2]);
	});

	it('extracts the error detail', () => {
		expect(errorDetail({ errors: [{ detail: 'Invalid key', status: 401 }] }, 'fallback')).toBe(
			'Invalid key',
		);
		expect(errorDetail({ detail: 'Nope' }, 'fallback')).toBe('Nope');
		expect(errorDetail({}, 'fallback')).toBe('fallback');
		expect(errorDetail('<html>'.repeat(100), 'fallback')).toBe('fallback');
	});

	it('normalizes country lists', () => {
		expect(parseCountryList(' cn, ru ')).toBe('CN,RU');
		expect(parseCountryList('')).toBeUndefined();
		expect(() => parseCountryList('China')).toThrow('two-letter ISO 3166 country code');
	});

	it('backs off exponentially with a cap, honouring Retry-After', () => {
		expect(backoffDelayMs(0)).toBeGreaterThanOrEqual(500);
		expect(backoffDelayMs(0)).toBeLessThan(750);
		expect(backoffDelayMs(10)).toBeLessThan(8250);
		expect(backoffDelayMs(0, 3)).toBe(3000);
		expect(backoffDelayMs(0, 120)).toBe(30000);
	});
});
