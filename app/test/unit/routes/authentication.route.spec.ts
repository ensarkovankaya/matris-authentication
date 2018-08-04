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
            const route = new AuthenticationRoute(service as any, validator as any, {} as any);
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
            const route = new AuthenticationRoute(service as any, validator as any, {} as any);
            throw new ShouldNotSucceed();
        } catch (e) {
            expect(e.name).to.be.eq('EnvironmentError');
            expect(e.variable).to.be.eq('ACCOUNT_SERVICE');
        }

        process.env.ACCOUNT_SERVICE = endpoint;
    });

    it('should raise SecretUndefined', () => {
        const endpoint = process.env.JWT_SECRET;
        process.env.JWT_SECRET = '';

        class MockAccountService {
            private options: any;

            public configure(options) {
                this.options = options;
            }
        }

        const service = new MockAccountService();
        const validator = new BaseRequestValidator();

        try {
            const route = new AuthenticationRoute(service as any, validator as any, {} as any);
            throw new ShouldNotSucceed();
        } catch (e) {
            expect(e.name).to.be.eq('EnvironmentError');
            expect(e.variable).to.be.eq('JWT_SECRET');
        }

        process.env.JWT_SECRET = endpoint;
    });

    describe('Password', () => {
        it('should call "data" method from RequestValidator', async () => {

            class MockJWTServices {
                public configure() {
                    // Configure
                }
            }

            class MockRequestValidator extends BaseRequestValidator {
                public data(req, location, onlyValidData: boolean = true, includeOptionals: boolean = true) {
                    this._data = {req, location, onlyValidData, includeOptionals};
                    throw new MethodCalled('data', this._data);
                }
            }

            const jwt = new MockJWTServices();
            const validator = new MockRequestValidator();
            const route = new AuthenticationRoute(new BaseAccountService() as any, validator as any, jwt as any);
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

            class MockJWTServices {
                public configure() {
                    // Configure
                }
            }

            class MockAccountService extends BaseAccountService {
                public by: any;
                public fields: any;

                public get(by: any, fields: any) {
                    this.by = by;
                    this.fields = fields;
                    throw new MethodCalled('get', {by, fields});
                }
            }

            const jwt = new MockJWTServices();
            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any, jwt as any);
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
            class MockJWTServices {
                public configure() {
                    // Configure
                }
            }

            class MockAccountService extends BaseAccountService {
                public get(by: any, fields: any) {
                    return null;
                }
            }

            const jwt = new MockJWTServices();
            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any, jwt as any);
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
            class MockJWTServices {
                public configure() {
                    // Configure
                }
            }
            class MockAccountService extends BaseAccountService {
                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: false};
                }
            }

            const jwt = new MockJWTServices();
            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any, jwt as any);
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
            class MockJWTServices {
                public configure() {
                    // Configure
                }
            }
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

            const jwt = new MockJWTServices();
            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any, jwt as any);
            const response = new MockResponse();
            await route.password({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(service.data).to.be.an('object');
            expect(service.data).to.be.deep.eq({email: 'mail@mail.com', password: '12345678'});
        });

        it('should return InvalidPasswordResponse', async () => {
            class MockJWTServices {

                public configure() {
                    // Configure
                }
            }
            class MockAccountService extends BaseAccountService {
                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: true, role: 'ADMIN'};
                }

                public password() {
                    return false;
                }
            }

            const jwt = new MockJWTServices();
            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any, jwt as any);

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

        it('should call "sign" method from JWTService', async () => {
            class MockJWTServices {
                public data: any;
                public overwrites: any;

                public configure() {
                    // Configure
                }

                public sign(data, overwrites) {
                    this.data = data;
                    this.overwrites = overwrites;
                    throw new MethodCalled('sign', {data, overwrites});
                }
            }
            class MockAccountService extends BaseAccountService {
                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: true, role: 'ADMIN'};
                }

                public password() {
                    return true;
                }
            }

            const jwt = new MockJWTServices();
            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any, jwt as any);

            const response = new MockResponse();
            await route.password({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(jwt.data).to.be.an('object');
            expect(jwt.data).to.have.keys(['id', 'email', 'role']);
            expect(jwt.data).to.be.deep.eq({id: '1'.repeat(24), email: 'mail@mail.com', role: 'ADMIN'});

            expect(jwt.overwrites).to.be.an('object');
            expect(jwt.overwrites).to.be.deep.eq({});
        });

        it('should call "sign" method from JWTService with overwrites', async () => {
            class MockJWTServices {
                public data: any;
                public overwrites: any;

                public configure() {
                    // Configure
                }

                public sign(data, overwrites) {
                    this.data = data;
                    this.overwrites = overwrites;
                    throw new MethodCalled('sign', {data, overwrites});
                }
            }
            class MockAccountService extends BaseAccountService {
                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: true, role: 'ADMIN'};
                }

                public password() {
                    return true;
                }
            }

            const jwt = new MockJWTServices();
            const service = new MockAccountService();
            const validator = new BaseRequestValidator({
                email: 'mail@mail.com',
                password: '12345678',
                expiresIn: 60 * 60
            });
            const route = new AuthenticationRoute(service as any, validator as any, jwt as any);

            const response = new MockResponse();
            await route.password({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(jwt.data).to.be.an('object');
            expect(jwt.data).to.have.keys(['id', 'email', 'role']);
            expect(jwt.data).to.be.deep.eq({id: '1'.repeat(24), email: 'mail@mail.com', role: 'ADMIN'});

            expect(jwt.overwrites).to.be.an('object');
            expect(jwt.overwrites).to.be.deep.eq({expiresIn: 3600});
        });

        it('should return SuccessResponse', async () => {
            class MockJWTServices {
                public configure() {
                    // Configure
                }

                public sign() {
                    return 'jwt-token';
                }
            }
            class MockAccountService extends BaseAccountService {
                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: true, role: 'ADMIN'};
                }

                public password() {
                    return true;
                }
            }

            const jwt = new MockJWTServices();
            const service = new MockAccountService();
            const validator = new BaseRequestValidator({email: 'mail@mail.com', password: '12345678'});
            const route = new AuthenticationRoute(service as any, validator as any, jwt as any);

            const response = new MockResponse();
            await route.password({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(200);
            expect(response._data).to.be.an('object');
            expect(response._data).to.have.key('data');
            expect(response._data.data).to.be.eq('jwt-token');
        });
    });

    describe('Validate', () => {
        it('should call "data" method from RequestValidator', async () => {

            class MockJWTServices {
                public configure() {
                    // Configure
                }
            }

            class MockRequestValidator extends BaseRequestValidator {
                public data(req, location, onlyValidData: boolean = true, includeOptionals: boolean = true) {
                    this._data = {req, location, onlyValidData, includeOptionals};
                    throw new MethodCalled('data', this._data);
                }
            }

            const jwt = new MockJWTServices();
            const validator = new MockRequestValidator();
            const route = new AuthenticationRoute(new BaseAccountService() as any, validator as any, jwt as any);
            const response = new MockResponse();
            await route.validate({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(validator._data).to.be.an('object');
            expect(validator._data).to.have.keys(['req', 'location', 'onlyValidData', 'includeOptionals']);
            expect(validator._data.location).to.be.deep.eq(['body']);
            expect(validator._data.onlyValidData).to.be.eq(true);
            expect(validator._data.includeOptionals).to.be.eq(true);
        });

        it('should raise InvalidData', async () => {

            class MockJWTServices {
                public token: string;

                public configure() {
                    // Configure
                }
            }

            const jwt = new MockJWTServices();
            const validator = new BaseRequestValidator(null);
            const route = new AuthenticationRoute(new BaseAccountService() as any, validator as any, jwt as any);
            const response = new MockResponse();
            await route.validate({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);
        });

        it('should call "verify" method from JWTService', async () => {

            class MockJWTServices {
                public token: string;

                public configure() {
                    // Configure
                }

                public verify(token) {
                    this.token = token;
                    throw new MethodCalled('verify', token);
                }
            }

            const jwt = new MockJWTServices();
            const validator = new BaseRequestValidator({token: 'jwt-token'});
            const route = new AuthenticationRoute(new BaseAccountService() as any, validator as any, jwt as any);
            const response = new MockResponse();
            await route.validate({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(jwt.token).to.be.a('string');
            expect(jwt.token).to.be.eq('jwt-token');
        });

        it('should return TokenExpiredResponse', async () => {

            class MockJWTServices {
                public token: string;

                public configure() {
                    // Configure
                }

                public verify() {
                    class TokenExpiredError extends Error {
                        public name = 'TokenExpiredError';
                    }
                    throw new TokenExpiredError();
                }
            }

            const jwt = new MockJWTServices();
            const validator = new BaseRequestValidator({token: 'jwt-token'});
            const route = new AuthenticationRoute(new BaseAccountService() as any, validator as any, jwt as any);
            const response = new MockResponse();
            await route.validate({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(400);
            expect(response._data).to.be.deep.eq({
                errors: [{
                    msg: 'TokenExpired',
                    location: 'body',
                    param: 'token'
                }],
                data: null
            });
        });

        it('should return InvalidTokenResponse', async () => {

            class MockJWTServices {
                public token: string;

                public configure() {
                    // Configure
                }

                public verify() {
                    class JsonWebTokenError extends Error {
                        public name = 'JsonWebTokenError';
                    }
                    throw new JsonWebTokenError();
                }
            }

            const jwt = new MockJWTServices();
            const validator = new BaseRequestValidator({token: 'jwt-token'});
            const route = new AuthenticationRoute(new BaseAccountService() as any, validator as any, jwt as any);
            const response = new MockResponse();
            await route.validate({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(400);
            expect(response._data).to.be.deep.eq({
                errors: [{
                    msg: 'InvalidToken',
                    location: 'body',
                    param: 'token'
                }],
                data: null
            });
        });

        it('should return SuccessResponse', async () => {

            class MockJWTServices {
                public token: string;

                public configure() {
                    // Configure
                }

                public verify() {
                    return {id: '12345', email: 'mail@mail.com', role: 'ADMIN'};
                }
            }

            const jwt = new MockJWTServices();
            const validator = new BaseRequestValidator({token: 'jwt-token'});
            const route = new AuthenticationRoute(new BaseAccountService() as any, validator as any, jwt as any);
            const response = new MockResponse();
            await route.validate({} as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(200);
            expect(response._data).to.be.deep.eq({data: {id: '12345', email: 'mail@mail.com', role: 'ADMIN'}});
        });
    });
});
