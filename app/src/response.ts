import { Response } from "express";
import { IAPIError } from './graphql/error';
import { IAPIResponse, IValidationError } from "./models/response.model";
import { IHttpResponse } from './services/http.service';

export class BaseResponse implements IAPIResponse<any> {
    public data: any;
    public status: number;
    public errors: IValidationError[] | null;
    private response: Response;

    constructor(res: Response) {
        this.response = res;
    }

    public send(): Response {
        return this.response.status(this.status).json(this.toJSON());
    }

    public toJSON(): IAPIResponse<any> {
        const response = this.errors ? {errors: this.errors} : {};
        return {
            ...response,
            data: this.data || null,
        };
    }
}

export class SuccessResponse extends BaseResponse {

    constructor(res: Response, data: any = null) {
        super(res);
        this.status = 200;
        this.data = data;
    }
}

export class ErrorResponse extends BaseResponse {

    constructor(res: Response, errors: IValidationError[]) {
        super(res);
        this.status = 400;
        this.errors = errors;
    }
}

export class ServerErrorResponse extends BaseResponse {

    constructor(res: Response) {
        super(res);
        this.status = 500;
    }
}
