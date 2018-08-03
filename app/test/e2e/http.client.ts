import * as axios from 'axios';
import { AxiosError, AxiosRequestConfig, AxiosResponse } from 'axios';
import { Logger } from 'matris-logger';
import { rootLogger } from '../../src/logger';

export class HttpClientError extends Error implements AxiosError {
    public name = 'HttpClientError';
    public config: AxiosRequestConfig;
    public code?: string;
    public request?: any;
    public response?: AxiosResponse;
    public status: number | undefined;
    public data: any;

    constructor(e: AxiosError) {
        super();
        this.config = e.config;
        this.code = e.code;
        this.request = e.request;
        this.response = e.response;
        this.status = this.response ? this.response.status : undefined;
        this.data = this.response ? this.response.data : undefined;
    }
}

export class HttpClient {

    private logger: Logger;
    private headers: {[key: string]: string};

    constructor(public baseurl: string, headers?: {[key: string]: string}) {
        this.logger = rootLogger.getLogger('HttpClient', ['test']);
        this.headers = headers || {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };
    }

    public setHeaders(headers: {[key: string]: string}) {
        this.headers = headers;
    }

    public password<T>(data: any) {
        return this.post<T>('password', data);
    }

    private async post<T>(url: string, data?: any): Promise<AxiosResponse<T>> {
        try {
            this.logger.debug('Post', {url, data});
            return await axios.default.request<T>({
                method: 'POST',
                url: this.baseurl + (url.startsWith('/') ? url : ('/' + url)),
                headers: this.headers,
                data
            });
        } catch (e) {
            this.logger.http('Post', e.request, e.response, {data: e.response.data});
            throw new HttpClientError(e);
        }
    }
}
