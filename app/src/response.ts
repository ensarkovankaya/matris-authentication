import { Response } from "express";
import { Location } from "express-validator/check/location";

export interface IValidationError {
    location: Location;
    param: string;
    msg: string;
}

export interface IAPIResponse<T> {
    data?: T;
    errors?: IValidationError[];
}

export class BaseResponse implements IAPIResponse<any> {
    public data?: any;
    public status: number;
    public errors?: IValidationError[];
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
