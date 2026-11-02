import { DEFAULT_MALICIOUS_THRESHOLD, MAX_CATEGORIES, MAX_COMMENT_LENGTH } from './constants';

export class InputValidationError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'InputValidationError';
	}
}

export interface ReputationFields {
	isWhitelisted?: unknown;
	totalReports?: unknown;
	abuseConfidenceScore?: unknown;
}

/**
 * Whether a /check result should be treated as malicious.
 *
 * Allowlisted addresses (public DNS resolvers and similar) come back with a score of 100
 * and no reports, so they are never malicious. Neither is any address without reports.
 */
export function isMalicious(
	result: ReputationFields,
	threshold: number = DEFAULT_MALICIOUS_THRESHOLD,
): boolean {
	if (result.isWhitelisted === true) return false;
	const totalReports = Number(result.totalReports ?? 0);
	if (!Number.isFinite(totalReports) || totalReports <= 0) return false;
	const score = Number(result.abuseConfidenceScore);
	return Number.isFinite(score) && score >= threshold;
}

const IPV4_OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4_PATTERN = new RegExp(`^${IPV4_OCTET}(\\.${IPV4_OCTET}){3}$`);
const IPV6_GROUP_PATTERN = /^[0-9a-f]{1,4}$/i;

export function isIPv4(value: string): boolean {
	return IPV4_PATTERN.test(value);
}

export function isIPv6(value: string): boolean {
	if (!value.includes(':')) return false;
	let address = value;
	const lastColon = address.lastIndexOf(':');
	const tail = address.slice(lastColon + 1);
	if (tail.includes('.')) {
		if (!isIPv4(tail)) return false;
		address = `${address.slice(0, lastColon + 1)}0:0`;
	}
	const halves = address.split('::');
	if (halves.length > 2) return false;
	if (halves.length === 2) {
		const head = halves[0] ? halves[0].split(':') : [];
		const rest = halves[1] ? halves[1].split(':') : [];
		const groups = [...head, ...rest];
		return groups.length <= 7 && groups.every((group) => IPV6_GROUP_PATTERN.test(group));
	}
	const groups = address.split(':');
	return groups.length === 8 && groups.every((group) => IPV6_GROUP_PATTERN.test(group));
}

export function ipVersion(value: string): 4 | 6 | undefined {
	if (isIPv4(value)) return 4;
	if (isIPv6(value)) return 6;
	return undefined;
}

export function isValidIp(value: string): boolean {
	return ipVersion(value) !== undefined;
}

export function isValidNetwork(value: string): boolean {
	const parts = value.split('/');
	if (parts.length !== 2) return false;
	const [address, prefix] = parts;
	const version = ipVersion(address);
	if (version === undefined || !/^\d{1,3}$/.test(prefix)) return false;
	return Number(prefix) <= (version === 4 ? 32 : 128);
}

export function validateIp(value: unknown): string {
	const ip = String(value ?? '').trim();
	if (!isValidIp(ip)) {
		throw new InputValidationError(`Not a valid IPv4 or IPv6 address: "${ip}"`);
	}
	return ip;
}

export function validateIpOrNetwork(value: unknown): string {
	const target = String(value ?? '').trim();
	const valid = target.includes('/') ? isValidNetwork(target) : isValidIp(target);
	if (!valid) {
		throw new InputValidationError(`Not a valid IP address or CIDR network: "${target}"`);
	}
	return target;
}

export function validateNetwork(value: unknown): string {
	const network = String(value ?? '').trim();
	if (!isValidNetwork(network)) {
		throw new InputValidationError(
			`Not a valid CIDR network: "${network}". Use the form 203.0.113.0/24 or 2001:db8::/48`,
		);
	}
	return network;
}

/** Accepts slugs or numeric IDs as an array or a comma separated string; removes duplicates. */
export function normalizeCategories(value: unknown): string[] {
	let items: unknown[];
	if (Array.isArray(value)) {
		items = value.flatMap((item) => String(item ?? '').split(','));
	} else if (typeof value === 'string' || typeof value === 'number') {
		items = String(value).split(',');
	} else {
		items = [];
	}
	const result: string[] = [];
	for (const item of items) {
		const category = String(item).trim();
		if (category && !result.includes(category)) result.push(category);
	}
	if (result.length === 0) {
		throw new InputValidationError(
			'At least one category is required, for example "ssh,brute-force"',
		);
	}
	if (result.length > MAX_CATEGORIES) {
		throw new InputValidationError(
			`At most ${MAX_CATEGORIES} categories are allowed per report, got ${result.length}`,
		);
	}
	return result;
}

const HAS_TIME = /\d[T ]\d/;
const HAS_TIMEZONE = /\d(Z|[+-]\d{2}:?\d{2})$/i;

/**
 * Converts a date to RFC 3339. Strings without a time zone are read as UTC.
 * Returns undefined for empty input.
 */
export function formatTimestamp(value: unknown): string | undefined {
	if (value === undefined || value === null || value === '') return undefined;
	if (value instanceof Date) {
		if (Number.isNaN(value.getTime())) throw new InputValidationError('Invalid report date');
		return value.toISOString();
	}
	if (typeof value === 'object' && typeof (value as { toISO?: unknown }).toISO === 'function') {
		return String((value as { toISO: () => string }).toISO());
	}
	const text = String(value).trim();
	if (!text) return undefined;
	const hasTime = HAS_TIME.test(text);
	const hasZone = hasTime && HAS_TIMEZONE.test(text);
	const candidate = hasTime && !hasZone ? `${text.replace(' ', 'T')}Z` : text.replace(' ', 'T');
	const parsed = new Date(candidate);
	if (Number.isNaN(parsed.getTime())) {
		throw new InputValidationError(
			`Invalid report date: "${text}". Use an ISO 8601 date such as 2026-11-02T10:00:00Z`,
		);
	}
	return hasZone ? candidate : parsed.toISOString();
}

export function truncateComment(value: unknown): string {
	if (value === undefined || value === null) return '';
	return String(value).slice(0, MAX_COMMENT_LENGTH);
}

export function parseCountryList(value: unknown): string | undefined {
	const codes = String(value ?? '')
		.split(/[\s,]+/)
		.map((code) => code.trim().toUpperCase())
		.filter(Boolean);
	for (const code of codes) {
		if (!/^[A-Z]{2}$/.test(code)) {
			throw new InputValidationError(`"${code}" is not a two-letter ISO 3166 country code`);
		}
	}
	return codes.length ? codes.join(',') : undefined;
}

export interface BulkReportRow {
	ip: string;
	categories: string[];
	timestamp?: string;
	comment: string;
}

export function toBulkReportRow(input: {
	ip: unknown;
	categories: unknown;
	timestamp?: unknown;
	comment?: unknown;
}): BulkReportRow {
	return {
		ip: validateIpOrNetwork(input.ip),
		categories: normalizeCategories(input.categories),
		timestamp: formatTimestamp(input.timestamp),
		comment: truncateComment(input.comment),
	};
}

function escapeCsvField(value: string): string {
	return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

/** Builds the IP,Categories,ReportDate,Comment CSV accepted by POST /bulk-report. */
export function buildBulkReportCsv(rows: BulkReportRow[]): string {
	const lines = ['IP,Categories,ReportDate,Comment'];
	for (const row of rows) {
		lines.push(
			[row.ip, row.categories.join(','), row.timestamp ?? '', row.comment]
				.map(escapeCsvField)
				.join(','),
		);
	}
	return `${lines.join('\n')}\n`;
}

export function chunk<T>(values: T[], size: number): T[][] {
	const chunks: T[][] = [];
	for (let start = 0; start < values.length; start += size) {
		chunks.push(values.slice(start, start + size));
	}
	return chunks;
}

export function parseBody(body: unknown): unknown {
	if (body === undefined || body === null || body === '') return undefined;
	if (typeof body === 'object' && !isBinary(body)) return body;
	const text = bodyToText(body);
	try {
		return JSON.parse(text);
	} catch {
		return text;
	}
}

export function bodyToText(body: unknown): string {
	if (body === undefined || body === null) return '';
	if (typeof body === 'string') return body;
	if (isBinary(body)) return Buffer.from(body as Uint8Array).toString('utf8');
	return JSON.stringify(body, null, 2);
}

function isBinary(value: unknown): boolean {
	return value instanceof Uint8Array || value instanceof ArrayBuffer;
}

export function unwrapData(body: unknown): unknown {
	if (body && typeof body === 'object' && !Array.isArray(body) && 'data' in body) {
		return (body as { data: unknown }).data;
	}
	return body;
}

export function errorDetail(body: unknown, fallback: string): string {
	if (body && typeof body === 'object') {
		const errors = (body as { errors?: unknown }).errors;
		if (Array.isArray(errors) && errors.length > 0) {
			const detail = (errors[0] as { detail?: unknown })?.detail;
			if (detail) return String(detail);
		}
		const detail = (body as { detail?: unknown }).detail;
		if (detail) return String(detail);
	}
	if (typeof body === 'string' && body.trim() && body.length <= 300) return body.trim();
	return fallback;
}

export function backoffDelayMs(attempt: number, retryAfterSeconds?: number): number {
	if (retryAfterSeconds !== undefined && Number.isFinite(retryAfterSeconds)) {
		return Math.min(Math.max(retryAfterSeconds, 0), 30) * 1000;
	}
	return Math.min(500 * 2 ** attempt, 8000) + Math.floor(Math.random() * 250);
}
