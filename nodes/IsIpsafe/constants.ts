export const PACKAGE_VERSION = '0.1.0';
export const USER_AGENT = `isipsafe-n8n/${PACKAGE_VERSION}`;
export const BASE_URL = 'https://isipsafe.com/api/v1';
export const CREDENTIAL_NAME = 'isIpsafeApi';
export const API_KEY_URL = 'https://isipsafe.com/login';

export const REQUEST_TIMEOUT_MS = 10_000;
export const MAX_GET_RETRIES = 2;

export const DEFAULT_MALICIOUS_THRESHOLD = 75;
export const MAX_CATEGORIES = 12;
export const MAX_COMMENT_LENGTH = 1024;
export const MAX_BULK_ROWS = 10_000;
export const MAX_REPORTS_PER_PAGE = 100;

export const BLOCKLIST_FORMATS = [
	'json',
	'txt',
	'csv',
	'stix',
	'ipset',
	'nftables',
	'nginx',
	'apache',
	'mikrotik',
] as const;

export type BlocklistFormat = (typeof BLOCKLIST_FORMATS)[number];

export const BLOCKLIST_FILES: Record<
	Exclude<BlocklistFormat, 'json'>,
	{ extension: string; mimeType: string }
> = {
	txt: { extension: 'txt', mimeType: 'text/plain' },
	csv: { extension: 'csv', mimeType: 'text/csv' },
	stix: { extension: 'json', mimeType: 'application/json' },
	ipset: { extension: 'ipset', mimeType: 'text/plain' },
	nftables: { extension: 'nft', mimeType: 'text/plain' },
	nginx: { extension: 'conf', mimeType: 'text/plain' },
	apache: { extension: 'conf', mimeType: 'text/plain' },
	mikrotik: { extension: 'rsc', mimeType: 'text/plain' },
};
