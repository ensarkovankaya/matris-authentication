import { expect } from 'chai';
import { ClientError, GraphQLError, Headers, Options, Variables } from 'graphql-request/dist/src/types';
import { describe, it } from 'mocha';
import { IGraphQLClient, UserService } from './user.service';

/**
 * Fake client for api request
 */
class FakeGraphQLClient implements Partial<IGraphQLClient> {
    private options;
    private url;
    private _status: number;
    private _data: any;
    private _errors: GraphQLError[];
    private readonly _headers: Headers;

    constructor(url: string = '', options?: Options) {
        this.url = url;
        this.options = options;
        this._headers = {};
    }

    public async request(query: string, variables?: Variables): Promise<any> {
        if (this._errors) {
            throw new ClientError({
                status: this._status,
                errors: this._errors,
                data: this._data
            }, {query, variables});
        }
        return this._data;
    }

    public setHeader(key: string, value: string) {
        this._headers[key] = value;
        return this;
    }

    public setResponse(data: any, errors?: GraphQLError[], status: number = 200) {
        this._data = data;
        this._errors = errors;
        this._status = status;
    }

}

describe('User Service Test', () => {
    describe('Email-Password Check', () => {
        it('should return true', async () => {
            const client = new FakeGraphQLClient();
            client.setResponse({
                valid: true
            });
            const service = new UserService(client);
            const valid = await service.isPasswordValid('email@example.com', '12345678');
            expect(valid).to.eq(true);
        });

        it('should return false', async () => {
            const client = new FakeGraphQLClient('');
            client.setResponse({
                valid: false
            });
            const service = new UserService(client);
            const valid = await service.isPasswordValid('email@example.com', '12345678');
            expect(valid).to.eq(false);
        });

        it('should raise schema error', async () => {
            try {
                const client = new FakeGraphQLClient();
                client.setResponse({
                    valid: 'asd'
                });
                const service = new UserService(client);
                await service.isPasswordValid('email@example.com', '12345678');
            } catch (e) {
                expect(e.name).to.eq('ResponseInvalidError');
            }
        });
    });

    describe('Get User', () => {
        it('should get user', async () => {
            const client = new FakeGraphQLClient();
            client.setResponse({
                user: {
                    _id: 'randomid',
                    email: 'example@gmail.com',
                    role: 'ADMIN'
                }
            });
            const service = new UserService(client);
            const user = await service.getUser({id: 'randomid'});
            expect(user).to.eql({_id: 'randomid', email: 'example@gmail.com', role: 'ADMIN'});
        });

        it('should get null', async () => {
            const client = new FakeGraphQLClient();
            client.setResponse({user: null});
            const service = new UserService(client);
            const user = await service.getUser({id: 'id'});
            expect(user).to.eq(null);
        });
    });
});
