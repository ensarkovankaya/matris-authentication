import { IValidationError } from '../models/response.model';
import { APIError } from './error';

export class GraphQLResponse<T> {

    constructor(public data: T, public errors: IValidationError[]) {
    }

    public hasErrors(raise: boolean = false): boolean {
        const hasError = this.errors ? this.errors.length > 0 : false;
        if (raise && hasError) {
            throw new APIError();
        }
        return hasError;
    }
}
