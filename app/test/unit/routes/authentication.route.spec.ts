import { expect } from 'chai';
import { describe, it } from 'mocha';
import "reflect-metadata";
import { AuthenticationRoute } from '../../../src/routes/authentication.route';

export class MethodCalled extends Error {
    public name = 'MethodCalled';

    constructor(public method: string, public args?: any) {
        super();
    }
}

class ShouldNotSucceed extends Error {
    public name = 'ShouldNotSucceed';
}

class ResponseSended extends Error {
    public name = 'ResponseSended';

    constructor(public status: number, public data: any) {
        super();
    }
}

class MockResponse {
    public _status: number;
    public _data: any;
    public sended: boolean;

    constructor(public raise: boolean = false) {
        this.sended = false;
    }

    public status(status: number): this {
        this._status = status;
        return this;
    }

    public json(data: any): this {
        this._data = data;
        // Checks response already sended
        if (this.sended) {
            throw new Error('Response already sended');
        }
        this.sended = true;
        if (this.raise) {
            throw new ResponseSended(this._status, data);
        }
        return this;
    }
}

class BaseRequestValidator {

    public _data: any;

    constructor(data?: any) {
        this._data = data;
    }

    public schema(schema: any) {
        return [];
    }

    public validate() {
        // Validates schema
    }

    public data(req, location, onlyValidData: boolean = true, includeOptionals: boolean = true) {
        return this._data;
    }
}

class BaseAccountService {
    public _get: any; // Return value from get method
    public _password: any; // Return value from password method
    public _options: any; // options from configure
    public callStack: Array<{method: string, args: any}>;

    constructor() {
        this.callStack = [];
    }

    public configure(options) {
        this._options = options;
    }

    public get(by: any, fields: any) {
        this.callStack.push({method: 'get', args: {by, fields}});
        return this._get;
    }

    public password(email: any, password: any) {
        this.callStack.push({method: 'password', args: {email, password}});
        return this._password;
    }
}

describe('Unit -> Routes -> AuthenticationRoute', () => {
    it('should initialize and call configure method from AccountService', () => {
        class MockAccountService {
            public configure(options) {
                throw new MethodCalled('configure', options);
            }
        }

        const service = new MockAccountService();
        const validator = new BaseRequestValidator();

        try {
            const route = new AuthenticationRoute(service as any, validator as any);
            throw new ShouldNotSucceed();
        } catch (e) {
            expect(e.name).to.be.eq('MethodCalled');
            expect(e.method).to.be.eq('configure');
            expect(e.args).to.be.an('object');
            expect(e.args).to.have.key('url');
            expect(e.args.url).to.be.a('string');
        }
    });

    it('should raise EndpointUndefined', () => {
        const endpoint = process.env.ACCOUNT_SERVICE;
        process.env.ACCOUNT_SERVICE = '';

        class MockAccountService {
            private options: any;

            public configure(options) {
                this.options = options;
            }
        }

        const service = new MockAccountService();
        const validator = new BaseRequestValidator();

        try {
            const route = new AuthenticationRoute(service as any, validator as any);
            throw new ShouldNotSucceed();
        } catch (e) {
            expect(e.name).to.be.eq('EndpointUndefined');
        }

        process.env.ACCOUNT_SERVICE = endpoint;
    });

    it('should raise SecretUndefined', () => {
        const endpoint = process.env.SECRET;
        process.env.SECRET = '';

        class MockAccountService {
            private options: any;

            public configure(options) {
                this.options = options;
            }
        }

        const service = new MockAccountService();
        const validator = new BaseRequestValidator();

        try {
            const route = new AuthenticationRoute(service as any, validator as any);
            throw new ShouldNotSucceed();
        } catch (e) {
            expect(e.name).to.be.eq('SecretUndefined');
        }

        process.env.SECRET = endpoint;
    });

    describe('Password', () => {
        it('should call "data" method from RequestValidator', async () => {

            class MockRequestValidator extends BaseRequestValidator {
                public data(req, location, onlyValidData: boolean = true, includeOptionals: boolean = true) {
                    this._data = {req, location, onlyValidData, includeOptionals};
                    throw new MethodCalled('data', this._data);
                }
            }

            const validator = new MockRequestValidator();
            const route = new AuthenticationRoute(new BaseAccountService() as any, validator as any);
            const response = new MockResponse();
            await route.password({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(validator._data).to.be.an('object');
            expect(validator._data).to.have.keys(['req', 'location', 'onlyValidData', 'includeOptionals']);
            expect(validator._data.location).to.be.deep.eq(['body']);
            expect(validator._data.onlyValidData).to.be.eq(true);
            expect(validator._data.includeOptionals).to.be.eq(true);
        });

        it('should call "get" method from AccountService', async () => {

            class MockAccountService extends BaseAccountService {
                public by: any;
                public fields: any;

                public get(by: any, fields: any) {
                    this.by = by;
                    this.fields = fields;
                    throw new MethodCalled('get', {by, fields});
                }
            }

            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any);
            const response = new MockResponse();
            await route.password({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(service.by).to.be.an('object');
            expect(service.by).to.be.deep.eq({email: 'mail@mail.com'});
            expect(service.fields).to.be.an('array');
            expect(service.fields).to.be.deep.eq(['_id', 'email', 'role', 'active']);
        });

        it('should return UserNotFoundResponse', async () => {

            class MockAccountService extends BaseAccountService {
                public get(by: any, fields: any) {
                    return null;
                }
            }

            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any);
            const response = new MockResponse();

            await route.password({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(400);
            expect(response._data).to.be.deep.eq({
                errors: [{
                    msg: 'UserNotFound',
                    location: 'body',
                    param: 'email'
                }],
                data: null
            });
        });

        it('should return UserNotActiveResponse', async () => {

            class MockAccountService extends BaseAccountService {
                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: false};
                }
            }

            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any);
            const response = new MockResponse();

            await route.password({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(400);
            expect(response._data).to.be.deep.eq({
                errors: [{
                    msg: 'UserNotActive',
                    location: 'body',
                    param: 'email'
                }],
                data: null
            });
        });

        it('should call "password" method', async () => {

            class MockAccountService extends BaseAccountService {
                public data: any;

                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: true, role: 'ADMIN'};
                }

                public password(email: string, password: string) {
                    this.data = {email, password};
                    throw new MethodCalled('password', {email, password});
                }
            }

            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any);
            const response = new MockResponse();
            await route.password({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(service.data).to.be.an('object');
            expect(service.data).to.be.deep.eq({email: 'mail@mail.com', password: '12345678'});
        });

        it('should return InvalidPasswordResponse', async () => {

            class MockAccountService extends BaseAccountService {
                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: true, role: 'ADMIN'};
                }

                public password() {
                    return false;
                }
            }

            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any);

            const response = new MockResponse();
            await route.password({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(400);
            expect(response._data).to.be.deep.eq({errors: [{
                msg: 'InvalidPassword',
                location: 'body',
                param: 'password'
            }], data: null});
        });

        it('should return SuccessResponse', async () => {
            class MockAccountService extends BaseAccountService {
                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: true, role: 'ADMIN'};
                }

                public password() {
                    return true;
                }
            }

            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any);

            const response = new MockResponse();
            await route.password({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(200);
            expect(response._data).to.be.an('object');
            expect(response._data).to.have.key('data');
            expect(response._data.data).to.be.a('string');
            expect(response._data.data).to.have.lengthOf(200);
        });
    });
});