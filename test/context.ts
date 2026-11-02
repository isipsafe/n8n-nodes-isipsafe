import type {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestOptions,
	ILoadOptionsFunctions,
	INodeExecutionData,
} from 'n8n-workflow';
import { vi } from 'vitest';

export interface FakeResponse {
	statusCode?: number;
	body?: unknown;
	headers?: IDataObject;
	networkError?: boolean;
}

export interface ContextOptions {
	params: IDataObject | ((itemIndex: number) => IDataObject);
	items?: INodeExecutionData[];
	apiKey?: string;
	responses?: FakeResponse[];
	continueOnFail?: boolean;
}

export function createContext(options: ContextOptions) {
	const queue = [...(options.responses ?? [])];
	const sent: IHttpRequestOptions[] = [];
	const respond = async (requestOptions: IHttpRequestOptions) => {
		sent.push(requestOptions);
		const next = queue.shift();
		if (!next) throw new Error('No fake response left');
		if (next.networkError)
			throw Object.assign(new Error('getaddrinfo ENOTFOUND isipsafe.com'), { code: 'ENOTFOUND' });
		return { statusCode: next.statusCode ?? 200, headers: next.headers ?? {}, body: next.body };
	};
	const httpRequest = vi.fn(async (requestOptions: IHttpRequestOptions) => respond(requestOptions));
	const httpRequestWithAuthentication = vi.fn(
		async (_credentialType: string, requestOptions: IHttpRequestOptions) => respond(requestOptions),
	);
	const prepareBinaryData = vi.fn(async (data: Buffer, fileName?: string, mimeType?: string) => ({
		data: data.toString('base64'),
		fileName,
		mimeType,
	}));

	const paramsFor = (itemIndex: number): IDataObject =>
		typeof options.params === 'function' ? options.params(itemIndex) : options.params;

	const context = {
		getInputData: () => options.items ?? [{ json: {} }],
		getNodeParameter: (name: string, itemIndex: number, fallback?: unknown) => {
			const params = paramsFor(itemIndex);
			if (name in params) return params[name];
			if (fallback !== undefined) return fallback;
			throw new Error(`Missing parameter ${name}`);
		},
		getNode: () => ({
			id: 'node-1',
			name: 'isIPsafe',
			type: 'n8n-nodes-isipsafe.isIpsafe',
			typeVersion: 1,
			position: [0, 0] as [number, number],
			parameters: {},
		}),
		getCredentials: vi.fn(async () => {
			if (options.apiKey === undefined) throw new Error('Node does not have any credentials set');
			return { apiKey: options.apiKey };
		}),
		continueOnFail: () => options.continueOnFail ?? false,
		helpers: { httpRequest, httpRequestWithAuthentication, prepareBinaryData },
	};

	return {
		context: context as unknown as IExecuteFunctions & ILoadOptionsFunctions,
		httpRequest,
		httpRequestWithAuthentication,
		prepareBinaryData,
		requests: () => sent,
	};
}
