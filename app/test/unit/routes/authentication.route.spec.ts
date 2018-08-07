import { expect } from 'chai';
import { Location } from 'express-validator/check/location';
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

class MockRequest {
    constructor(public body: any = {},
                public params: any = {},
                public query: any = {},
                public headers: any = {},
                public cookies: any = {}) {}
}

class MockRequestValidator {

    public schema(schema: any) {
        return [];
    }

    public validate() {
        // Validates schema
    }

    public data(req: MockRequest, location: Location[], onlyValidData?, includeOptionals?): any {
        let data = {};
        for (const loc of location) {
            const requestData = req[loc] || {};
            data = {...data, ...requestData};
        }
        return data;
    }
}

class MockAccountService {
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

class MockAuthService {
    public config: any;

    public configure(config) {
        this.config = config;
    }
}

describe('Unit -> Routes -> AuthenticationRoute', () => {
    it('should initialize and call configure method from AccountService', () => {
        class AccountService {
            public configure(options) {
                throw new MethodCalled('configure', options);
            }
        }

        try {
            const route = new AuthenticationRoute(
                new AccountService() as any,
                new MockRequestValidator() as any, {} as any);
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

        class AccountService {
            private options: any;

            public configure(options) {
                this.options = options;
            }
        }

        try {
            const route = new AuthenticationRoute(
                new AccountService() as any,
                new MockRequestValidator() as any, {} as any
            );
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

        class AccountService {
            private options: any;

            public configure(options) {
                this.options = options;
            }
        }

        try {
            const route = new AuthenticationRoute(
                new AccountService() as any,
                new MockRequestValidator() as any, {} as any
            );
            throw new ShouldNotSucceed();
        } catch (e) {
            expect(e.name).to.be.eq('EnvironmentError');
            expect(e.variable).to.be.eq('JWT_SECRET');
        }

        process.env.JWT_SECRET = endpoint;
    });

    describe('Password', () => {
        it('should call "data" method from RequestValidator', async () => {

            class RequestValidator extends MockRequestValidator {
                public args: any;

                public data(req, location) {
                    this.args = {req, location};
                    throw new MethodCalled('data', req);
                    return {};
                }
            }

            const validator = new RequestValidator();
            const route = new AuthenticationRoute(
                new MockAccountService() as any, validator as any, new MockAuthService() as any
            );

            const response = new MockResponse();
            const request = new MockRequest({a: 1, b: 2});
            await route.password(request as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(validator.args).to.be.an('object');
            expect(validator.args).to.have.keys(['req', 'location']);
            expect(validator.args.location).to.be.deep.eq(['body']);
            expect(validator.args.req).to.be.an('object');
            expect(validator.args.req).to.be.deep.eq(request);
        });

        it('should raise IvalidData', async () => {
            const route = new AuthenticationRoute(
                new MockAccountService() as any,
                new MockRequestValidator() as any,
                new MockAuthService() as any
            );

            const request = new MockRequest({email: 'mail@mail.com', password: '12345678'});
            const response = new MockResponse();

            await route.password(request as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);
        });

        it('should call "get" method from AccountService', async () => {

            class AccountService extends MockAccountService {
                public by: any;
                public fields: any;

                public get(by: any, fields: any) {
                    this.by = by;
                    this.fields = fields;
                    throw new MethodCalled('get', {by, fields});
                }
            }

            const service = new AccountService();

            const route = new AuthenticationRoute(
                service as any,
                new MockRequestValidator() as any,
                new MockAuthService() as any
            );

            const request = new MockRequest({
                email: 'mail@mail.com',
                password: '12345678',
                atExpiresIn: '1h',
                rtExpiresIn: '2h'
            });
            const response = new MockResponse();
            await route.password(request as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(service.by).to.be.an('object');
            expect(service.by).to.be.deep.eq({email: 'mail@mail.com'});
            expect(service.fields).to.be.an('array');
            expect(service.fields).to.be.deep.eq(['_id', 'email', 'role', 'active']);
        });

        it('should return UserNotFoundResponse', async () => {

            class AccountService extends MockAccountService {
                public get(by: any, fields: any) {
                    return null;
                }
            }

            const route = new AuthenticationRoute(
                new AccountService() as any, new MockRequestValidator() as any, new MockAuthService() as any
            );

            const response = new MockResponse();
            const request = new MockRequest({
                email: 'mail@mail.com',
                password: '12345678',
                atExpiresIn: '1h',
                rtExpiresIn: '2h'
            });

            await route.password(request as any, response as any);

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
            class AccountService extends MockAccountService {
                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: false};
                }
            }

            const route = new AuthenticationRoute(
                new AccountService() as any, new MockRequestValidator() as any, new MockAuthService() as any
            );

            const response = new MockResponse();
            const request = new MockRequest({
                email: 'mail@mail.com',
                password: '12345678',
                atExpiresIn: '1h',
                rtExpiresIn: '2h'
            });

            await route.password(request as any, response as any);

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
            class AccountService extends MockAccountService {
                public data: any;

                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: true, role: 'ADMIN'};
                }

                public password(email: string, password: string) {
                    this.data = {email, password};
                    throw new MethodCalled('password', {email, password});
                }
            }

            const service = new AccountService();
            const route = new AuthenticationRoute(
                service as any, new MockRequestValidator() as any, new MockAuthService() as any
            );

            const response = new MockResponse();
            const request = new MockRequest({
                email: 'mail@mail.com',
                password: '12345678',
                atExpiresIn: '1h',
                rtExpiresIn: '2h'
            });
            await route.password(request as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(service.data).to.be.an('object');
            expect(service.data).to.be.deep.eq({email: 'mail@mail.com', password: '12345678'});
        });

        it('should return InvalidPasswordResponse', async () => {
            class AccountService extends MockAccountService {
                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: true, role: 'ADMIN'};
                }

                public password() {
                    return false;
                }
            }

            const route = new AuthenticationRoute(
                new AccountService() as any, new MockRequestValidator() as any, new MockAuthService() as any
            );

            const response = new MockResponse();
            const request = new MockRequest({
                email: 'mail@mail.com',
                password: '12345678',
                atExpiresIn: '1h',
                rtExpiresIn: '2h'
            });
            await route.password(request as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(400);
            expect(response._data).to.be.deep.eq({errors: [{
                msg: 'InvalidPassword',
                location: 'body',
                param: 'password'
            }], data: null});
        });

        it('should call "Authenticate" method from AuthService', async () => {
            class AuthService extends MockAuthService {
                public id: any;
                public role: any;
                public accessTokenExpiresIn: any;
                public refreshTokenExpiresIn: any;
                public data: any;

                public authenticate(id, role, accessTokenExpiresIn, refreshTokenExpiresIn, data?) {
                    this.id = id;
                    this.role = role;
                    this.accessTokenExpiresIn = accessTokenExpiresIn;
                    this.refreshTokenExpiresIn = refreshTokenExpiresIn;
                    this.data = data;
                    throw new MethodCalled('authenticate');
                }
            }
            class AccountService extends MockAccountService {
                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: true, role: 'ADMIN'};
                }

                public password() {
                    return true;
                }
            }

            const auth = new AuthService();

            const route = new AuthenticationRoute(
                new AccountService() as any, new MockRequestValidator() as any, auth as any
            );

            const response = new MockResponse();
            const request = new MockRequest({
                email: 'mail@mail.com',
                password: '12345678',
                atExpiresIn: '1h',
                rtExpiresIn: '2h'
            });
            await route.password(request as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(auth.data).to.be.eq(undefined);
            expect(auth.id).to.be.eq('1'.repeat(24));
            expect(auth.role).to.be.eq('ADMIN');
            expect(auth.accessTokenExpiresIn).to.be.eq('1h');
            expect(auth.refreshTokenExpiresIn).to.be.eq('2h');
        });

        it('should return SuccessResponse', async () => {
            class AuthServices {
                public configure() {
                    // Configure
                }

                public authenticate() {
                    return {
                        accessToken: {
                            token: 'jwt-token',
                            tokenType: 'Bearer',
                            expiresAt: 123
                        },
                        refreshToken: {
                            token: 'jwt-token',
                            tokenType: 'Bearer',
                            expiresAt: 1234,
                            notBefore: 123
                        }
                    };
                }
            }
            class AccountService extends MockAccountService {
                public get(by: any, fields: any) {
                    return {id: '1'.repeat(24), email: 'mail@mail.com', active: true, role: 'ADMIN'};
                }

                public password() {
                    return true;
                }
            }

            const route = new AuthenticationRoute(
                new AccountService() as any, new MockRequestValidator() as any, new AuthServices() as any
            );

            const response = new MockResponse();
            const request = new MockRequest({
                email: 'mail@mail.com',
                password: '12345678',
                atExpiresIn: '1h',
                rtExpiresIn: '2h'
            });
            await route.password(request as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(200);
            expect(response._data).to.be.an('object');
            expect(response._data).to.have.key('data');

            expect(response._data.data).to.be.an('object');
            expect(response._data.data).to.be.deep.eq({
                accessToken: {
                    token: 'jwt-token',
                    tokenType: 'Bearer',
                    expiresAt: 123
                },
                refreshToken: {
                    token: 'jwt-token',
                    tokenType: 'Bearer',
                    expiresAt: 1234,
                    notBefore: 123
                }
            });
        });
    });

    describe('Validate', () => {
        it('should call "data" method from RequestValidator', async () => {

            class RequestValidator extends MockRequestValidator {
                public args: any;

                public data(req, location) {
                    this.args = {req, location};
                    throw new MethodCalled('data', this.args);
                }
            }

            const validator = new RequestValidator();
            const route = new AuthenticationRoute(
                new MockAccountService() as any, validator as any, new MockAuthService() as any
            );

            const response = new MockResponse();
            await route.validate(new MockRequest() as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(validator.args).to.be.an('object');
            expect(validator.args).to.have.keys(['req', 'location']);
            expect(validator.args.location).to.be.deep.eq(['body']);
        });

        it('should raise InvalidData', async () => {
            const route = new AuthenticationRoute(
                new MockAccountService() as any, new MockRequestValidator() as any, new MockAuthService() as any
            );
            const response = new MockResponse();
            await route.validate(new MockRequest() as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);
        });

        it('should call "verify" method from AuthService', async () => {

            class AuthService {
                public token: string;

                public configure() {
                    // Configure
                }

                public verify(token) {
                    this.token = token;
                    throw new MethodCalled('verify', token);
                }
            }

            const auth = new AuthService();
            const validator = new MockRequestValidator();
            const route = new AuthenticationRoute(new MockAccountService() as any, validator as any, auth as any);

            const response = new MockResponse();
            const request = new MockRequest({token: 'jwt-token'});

            await route.validate(request as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(auth.token).to.be.a('string');
            expect(auth.token).to.be.eq('jwt-token');
        });

        it('should return TokenExpiredResponse', async () => {

            class AuthService {
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

            const route = new AuthenticationRoute(
                new MockAccountService() as any, new MockRequestValidator() as any, new AuthService() as any
            );

            const response = new MockResponse();
            const request = new MockRequest({token: 'jwt-token'});
            await route.validate(request as any, response as any);

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

            class AuthService {
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

            const route = new AuthenticationRoute(
                new MockAccountService() as any, new MockRequestValidator() as any, new AuthService() as any
            );

            const response = new MockResponse();
            const request = new MockRequest({token: 'jwt-token'});
            await route.validate(request as any, response as any);

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

            class AuthService {
                public token: string;

                public configure() {
                    // Configure
                }

                public verify() {
                    return {sub: '12345', jit: 'abc', aud: 'ADMIN'};
                }
            }

            const route = new AuthenticationRoute(
                new MockAccountService() as any, new MockRequestValidator() as any, new AuthService() as any
            );

            const response = new MockResponse();
            const request = new MockRequest({token: 'jwt-token'});

            await route.validate(request as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(200);
            expect(response._data).to.be.deep.eq({data: {sub: '12345', jit: 'abc', aud: 'ADMIN'}});
        });
    });

    describe('Refresh', () => {
        it('should call "data" method from RequestValidator', async () => {

            class RequestValidator extends MockRequestValidator {
                public args: any;

                public data(req, location) {
                    this.args = {req, location};
                    throw new MethodCalled('data', this.args);
                }
            }

            const validator = new RequestValidator();
            const route = new AuthenticationRoute(
                new MockAccountService() as any, validator as any, new MockAuthService() as any
            );

            const response = new MockResponse();
            await route.refresh(new MockRequest() as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(validator.args).to.be.an('object');
            expect(validator.args).to.have.keys(['req', 'location']);
            expect(validator.args.location).to.be.deep.eq(['body']);
        });

        it('should raise InvalidData', async () => {
            const route = new AuthenticationRoute(
                new MockAccountService() as any, new MockRequestValidator() as any, new MockAuthService() as any
            );
            const response = new MockResponse();
            await route.refresh(new MockRequest() as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);
        });

        it('should call "refresh" method from AuthService', async () => {

            class AuthService extends MockAuthService {

                public accessToken: any;
                public refreshToken: any;
                public atExpiresIn: any;
                public rtExpiresIn: any;

                public refresh(accessToken, refreshToken, atExpiresIn, rtExpiresIn) {
                    this.accessToken = accessToken;
                    this.refreshToken = refreshToken;
                    this.atExpiresIn = atExpiresIn;
                    this.rtExpiresIn = rtExpiresIn;
                    throw new MethodCalled('refresh');
                }
            }

            const auth = new AuthService();

            const router = new AuthenticationRoute(
                new MockAccountService() as any, new MockRequestValidator() as any, auth as any
            );
            const response = new MockResponse();
            const request = new MockRequest({
                accessToken: 'access-token',
                refreshToken: 'refresh-token',
                atExpiresIn: '1h',
                rtExpiresIn: '2h'
            });

            await router.refresh(request as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(500);

            expect(auth.accessToken).to.be.eq('access-token');
            expect(auth.refreshToken).to.be.eq('refresh-token');
            expect(auth.atExpiresIn).to.be.eq('1h');
            expect(auth.rtExpiresIn).to.be.eq('2h');
        });

        it('should response with TokenExpiredResponse', async () => {

            class AuthService extends MockAuthService {

                public refresh() {
                    class TokenExpiredError extends Error {
                        public name = 'TokenExpiredError';
                    }
                    throw new TokenExpiredError();
                }
            }

            const auth = new AuthService();

            const router = new AuthenticationRoute(
                new MockAccountService() as any, new MockRequestValidator() as any, auth as any
            );
            const response = new MockResponse();
            const request = new MockRequest({
                accessToken: 'access-token',
                refreshToken: 'refresh-token',
                atExpiresIn: '1h',
                rtExpiresIn: '2h'
            });

            await router.refresh(request as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(400);
            expect(response._data).to.be.deep.eq({
                data: null,
                errors: [
                    {
                        msg: 'TokenExpired',
                        location: 'body',
                        param: 'token'
                    }
                ]
            });
        });

        it('should response with InvalidTokenResponse', async () => {

            class AuthService extends MockAuthService {

                public refresh() {
                    class JsonWebTokenError extends Error {
                        public name = 'JsonWebTokenError';
                    }
                    throw new JsonWebTokenError();
                }
            }

            const auth = new AuthService();

            const router = new AuthenticationRoute(
                new MockAccountService() as any, new MockRequestValidator() as any, auth as any
            );
            const response = new MockResponse();
            const request = new MockRequest({
                accessToken: 'access-token',
                refreshToken: 'refresh-token',
                atExpiresIn: '1h',
                rtExpiresIn: '2h'
            });

            await router.refresh(request as any, response as any);

            expect(response.sended).to.be.eq(true);
            expect(response._status).to.be.eq(400);
            expect(response._data).to.be.deep.eq({
                data: null,
                errors: [
                    {
                        msg: 'InvalidToken',
                        location: 'body',
                        param: 'token'
                    }
                ]
            });
        });
    });
});
