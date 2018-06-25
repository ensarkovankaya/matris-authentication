import { GraphQLClient } from "graphql-request";
import { ClientError, GraphQLError, Options, Variables } from 'graphql-request/dist/src/types';
import { Service } from "typedi";
import { IAccountModel } from '../models/account.model';

export interface IGraphQLClient {
    new(url: string, options?: Options);

    request<T extends any>(query: string, variables?: Variables): Promise<T>;

    setHeader(key: string, value: string);
}

interface IAPIResponse<T> {
    errors: GraphQLError[];
    status: number;
    data?: T;
}

export class APIValidationError extends Error {

    public name = 'APIValidationError';
    public errors: GraphQLError[];

    constructor(errors: GraphQLError[]) {
        super();
        this.errors = errors;
    }
}

export class APIResponse<T> implements IAPIResponse<T> {
    public errors: GraphQLError[];
    public status: number;
    public data?: T;

    constructor(status: number, data: T, errors: GraphQLError[] = []) {
        this.status = status;
        this.errors = errors || [];
        this.data = data;
    }

    public hasErrors(): boolean {
        return this.errors ? this.errors.length > 0 : false;
    }

    public hasError(name: string, raise: boolean = false): boolean {
        const hasError = this.errors ? this.errors.filter(e => e.message === name).length > 0 : false;
        if (hasError && raise) {
            throw new APIValidationError(this.errors);
        }
        return hasError;
    }

    public raise() {
        if (this.hasErrors()) {
            throw new APIValidationError(this.errors);
        }
    }
}

@Service('user.service')
export class UserService {

    private static handleResponse<T>(data: any): APIResponse<T> {
        return new APIResponse<T>(200, data);
    }

    /***
     * Checks error is Validation error or not.
     * @param {ClientError} err
     * @return {APIResponse<T>}
     */
    private static handleError<T>(err: ClientError): APIResponse<T> {
        if (err.response && err.response.errors) {
            return new APIResponse<T>(err.response.status, err.response.data, err.response.errors);
        }
        throw err;
    }

    constructor(private client: Partial<IGraphQLClient> = new GraphQLClient(process.env.USER_SERVICE_ENDPOINT)) {
        client.setHeader('Content-Type', 'application/json');
        client.setHeader('Accept', 'application/json');
    }

    public async getUserByEmail(email: string):
        Promise<IAccountModel | null> {
        try {
            const query = `query getUser($email: String!) {
                    user: get(email: $email) {
                        _id
                        email,
                        role
                    }
            }`;
            const response = await this.call<{ user: IAccountModel | null }>(query, {email});
            response.raise();
            return response.data.user;
        } catch (err) {
            console.error('UserService:GetUser', err);
            throw err;
        }
    }

    public async isPasswordValid(email: string, password: string) {
        try {
            const query = `query isPasswordValid($email: String!, $password: String!) {
                    valid: password(email: $email, password: $password)
            }`;
            const response = await this.call<{ valid: boolean }>(query, {email, password});
            if (response.hasErrors()) {
                return false;
            }
            return response.data.valid;
        } catch (err) {
            console.error('UserService:IsPasswordValid', err);
            throw err;
        }
    }

    private async call<T>(query: string, variables?: { [key: string]: any }):
        Promise<APIResponse<T>> {
        try {
            return await this.client.request<T>(query, variables)
                .then(data => UserService.handleResponse<T>(data))
                .catch(err => UserService.handleError<T>(err));
        } catch (err) {
            console.error('UserService:Call', err);
            throw err;
        }
    }
}
