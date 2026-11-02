import type {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestMethods,
	IHttpRequestOptions,
	ILoadOptionsFunctions,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, NodeOperationError, sleep } from 'n8n-workflow';

import {
	API_KEY_URL,
	BASE_URL,
	CREDENTIAL_NAME,
	MAX_GET_RETRIES,
	REQUEST_TIMEOUT_MS,
	USER_AGENT,
} from './constants';
import { backoffDelayMs, errorDetail, parseBody } from './utils';

type Context = IExecuteFunctions | ILoadOptionsFunctions;

export interface ApiRequest {
	method: IHttpRequestMethods;
	path: string;
	qs?: IDataObject;
	body?: string | IDataObject;
	contentType?: string;
	requireKey?: boolean;
	expectText?: boolean;
	retry?: boolean;
	acceptStatuses?: number[];
	itemIndex?: number;
}

export interface ApiResponse {
	statusCode: number;
	headers: IDataObject;
	body: unknown;
}

interface RawResponse {
	statusCode: number;
	headers?: IDataObject;
	body?: unknown;
}

/** True when an isIPsafe credential with a non-empty key is attached to the node. */
export async function hasApiKey(this: Context): Promise<boolean> {
	try {
		const credentials = await this.getCredentials(CREDENTIAL_NAME);
		return typeof credentials?.apiKey === 'string' && credentials.apiKey.trim() !== '';
	} catch {
		return false;
	}
}

export function cleanQuery(qs: IDataObject = {}): IDataObject {
	const result: IDataObject = {};
	for (const [name, value] of Object.entries(qs)) {
		if (value === undefined || value === null || value === '' || value === false) continue;
		result[name] = value === true ? 'true' : value;
	}
	return result;
}

/**
 * Calls the isIPsafe API. The key is attached by n8n's credential layer as a Bearer header
 * when a credential is selected; lookups also work anonymously. GET requests are retried
 * on network errors and 5xx responses, other methods are sent once.
 */
export async function isipsafeApiRequest(this: Context, request: ApiRequest): Promise<ApiResponse> {
	const authenticated = await hasApiKey.call(this);
	if (request.requireKey && !authenticated) {
		throw new NodeOperationError(this.getNode(), 'This operation needs an isIPsafe API key', {
			itemIndex: request.itemIndex,
			description: `Create a free key at ${API_KEY_URL} and select an isIPsafe API credential on this node.`,
		});
	}

	const headers: IDataObject = {
		Accept: request.expectText ? '*/*' : 'application/json',
		'User-Agent': USER_AGENT,
	};
	if (request.contentType) headers['Content-Type'] = request.contentType;

	const options: IHttpRequestOptions = {
		method: request.method,
		url: `${BASE_URL}${request.path}`,
		qs: cleanQuery(request.qs),
		headers,
		returnFullResponse: true,
		ignoreHttpStatusErrors: true,
		timeout: REQUEST_TIMEOUT_MS,
		json: !request.expectText && typeof request.body !== 'string',
	};
	if (request.body !== undefined) options.body = request.body;
	if (request.expectText) options.encoding = 'text';

	const retries = request.method === 'GET' && request.retry !== false ? MAX_GET_RETRIES : 0;

	for (let attempt = 0; ; attempt++) {
		const lastAttempt = attempt >= retries;
		let raw: RawResponse;
		try {
			raw = (
				authenticated
					? await this.helpers.httpRequestWithAuthentication.call(this, CREDENTIAL_NAME, options)
					: await this.helpers.httpRequest(options)
			) as RawResponse;
		} catch (error) {
			if (!lastAttempt) {
				await sleep(backoffDelayMs(attempt));
				continue;
			}
			throw new NodeApiError(this.getNode(), error as JsonObject, {
				message: 'Could not reach the isIPsafe API',
				itemIndex: request.itemIndex,
			});
		}

		const statusCode = Number(raw.statusCode ?? 200);
		if (statusCode >= 500 && !lastAttempt) {
			await sleep(backoffDelayMs(attempt));
			continue;
		}

		const body = parseBody(raw.body);
		const response: ApiResponse = { statusCode, headers: raw.headers ?? {}, body };
		if (statusCode < 400 || request.acceptStatuses?.includes(statusCode)) return response;
		throw apiError.call(this, response, request.itemIndex);
	}
}

function apiError(this: Context, response: ApiResponse, itemIndex?: number): NodeApiError {
	const { statusCode, body, headers } = response;
	const message = errorDetail(body, `isIPsafe API returned HTTP ${statusCode}`);
	let description: string | undefined;
	if (statusCode === 401) {
		description = `The API key was rejected. Check the isIPsafe API credential or create a new key at ${API_KEY_URL}.`;
	} else if (statusCode === 429) {
		const retryAfter = headers['retry-after'] ?? headers['Retry-After'];
		description = retryAfter
			? `Rate limit reached. Try again in ${String(retryAfter)} seconds.`
			: 'Rate limit reached. Add an API key to raise the daily lookup limit.';
	}
	const errorBody: JsonObject =
		body && typeof body === 'object' && !Array.isArray(body)
			? (body as JsonObject)
			: { message, statusCode };
	return new NodeApiError(this.getNode(), errorBody, {
		message,
		description,
		httpCode: String(statusCode),
		itemIndex,
	});
}
