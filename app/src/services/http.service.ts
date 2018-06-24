import axios, { AxiosError, AxiosResponse } from 'axios';
import { Service } from 'typedi';

export interface IHttpServiceConfig {
    headers?: { [key: string]: string };
}

export interface IHttpResponse {
    data: any;
    status: number;
    statusText: string;
}

export interface IHttpService {
    post(url: string, data?: any, config?: any): Promise<IHttpResponse>;
}

@Service('http.service')
export class HttpService implements IHttpService {

    private static handleError(err: AxiosError): IHttpResponse {
        console.log('HttpService:HandleError', err);
        if (err.response) {
            return {
                data: err.response.data,
                status: err.response.status,
                statusText: err.response.statusText
            };
        }
        throw err;
    }

    private static handleResponse(res: AxiosResponse): IHttpResponse {
        return {
            data: res.data,
            status: res.status,
            statusText: res.statusText
        };
    }

    public async post(url: string, data: any, config?: IHttpServiceConfig) {
        return await axios.post(url, data, config)
            .then(HttpService.handleResponse)
            .catch(HttpService.handleError);
    }
}
