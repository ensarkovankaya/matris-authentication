import { Request, Response, Router } from 'express';
import { AccountService } from 'matris-account-api';
import { UserSchema } from 'matris-account-api/dist/models/user';
import { Logger } from 'matris-logger/dist/logger';
import { Service } from 'typedi';
import { EnvironmentError, InvalidData } from '../errors';
import { rootLogger } from '../logger';
import {
    InvalidPasswordResponse,
    SuccessResponse,
    TokenExpiredResponse,
    UserNotActiveResponse,
    UserNotFoundResponse
} from '../response';
import { InvalidTokenResponse, TokenNotBeforeResponse } from '../response';
import { AuthenticationService } from '../services/auth.service';
import { RequestValidatorService } from '../services/request.validator.service';

@Service()
export class AuthenticationRoute {

    public router: Router;
    private logger: Logger;

    constructor(private ac: AccountService, private vl: RequestValidatorService, private auth: AuthenticationService) {
        this.logger = rootLogger.getLogger('AuthenticationRoute', ['route']);
        this.router = Router({caseSensitive: true});
        this.configure();
        this.routes();
    }

    /**
     * Configure services
     */
    public configure() {
        // Configure Account Service
        const endpoint = process.env.ACCOUNT_SERVICE;
        if (!endpoint) {
            throw new EnvironmentError('ACCOUNT_SERVICE');
        }
        this.ac.configure({url: endpoint});

        const secret = process.env.JWT_SECRET;
        if (!secret) {
            throw new EnvironmentError('JWT_SECRET');
        }

        // Configure JWT Service
        this.auth.configure({secret});
    }

    /**
     * Authenticate user with email and password
     * @param {Request} req
     * @param {Response} res
     */
    public async password(req: Request, res: Response) {
        // Get data from request
        const data = this.vl.data<{
            email: string;
            password: string;
            atExpiresIn: number;
            rtExpiresIn: number;
        }>(req, ['body']);

        if (!data || !data.email || !data.password || !data.atExpiresIn || !data.rtExpiresIn) {
            throw new InvalidData();
        }

        // Get user from AccountService
        let user: UserSchema;
        try {
            user = await this.ac.get({email: data.email}, ['_id', 'email', 'role', 'active']);
            this.logger.debug('User recived.', {user});
        } catch (e) {
            this.logger.error('Getting user from AccountService failed.', e);
            throw e;
        }

        // Check user exists and active
        if (!user) {
            return new UserNotFoundResponse(res).send();
        } else if (!user.active) {
            return new UserNotActiveResponse(res).send();
        }

        let valid = false;
        try {
            // Check is password valid
            valid = await this.ac.password(data.email, data.password);
            this.logger.debug('Password validated.', {valid});
        } catch (e) {
            this.logger.error('Checking password failed.', e);
            throw e;
        }

        // If password not valid return InvalidPasswordResponse
        if (!valid) {
            return new InvalidPasswordResponse(res).send();
        }

        try {
            // Authenticate user
            const tokens = await this.auth.authenticate(
                user.id,
                user.role,
                data.atExpiresIn,
                data.rtExpiresIn
            );
            this.logger.debug('User data signed.', {tokens});
            return new SuccessResponse(res, tokens).send();
        } catch (e) {
            this.logger.error('Signing user data failed.', e);
            throw e;
        }
    }

    /**
     * Validates jwt token if token valid returns decoded token.
     * If token expired returns TokenExpiredResponse
     * If token invalid returns InvalidTokenResponse
     * @param {Request} req
     * @param {Response} res
     */
    public async verify(req: Request, res: Response) {
        // Get data from request
        const data = this.vl.data<{ token: string }>(req, ['body']);

        if (!data || !data.token) {
            throw new InvalidData();
        }

        try {
            // Verify Token
            const payload = await this.auth.verify<any>(data.token);
            this.logger.debug('Token verified.', {payload});
            return new SuccessResponse(res, payload).send();
        } catch (e) {
            if (e.name === 'TokenExpiredError') {
                this.logger.warn('Token expired.', e);
                return new TokenExpiredResponse(res).send();
            } else if (e.name === 'JsonWebTokenError') {
                this.logger.warn('Token invalid.', e);
                return new InvalidTokenResponse(res).send();
            }
            this.logger.error('Token decoding failed.', e);
            throw e;
        }
    }

    /**
     * Returns new json web token for user if tokens are valid
     * @param {Request} req
     * @param {Response} res
     */
    public async refresh(req: Request, res: Response) {
        // Get data from request
        const data = this.vl.data<{
            accessToken: string;
            refreshToken: string;
            atExpiresIn: number | string;
            rtExpiresIn: number | string;
        }>(req, ['body']);

        if (!data || !data.accessToken || !data.refreshToken || !data.atExpiresIn || !data.rtExpiresIn) {
            throw new InvalidData();
        }

        try {
            // Refresh Token
            const tokens = await this.auth.refresh(
                data.accessToken,
                data.refreshToken,
                data.atExpiresIn,
                data.rtExpiresIn
            );
            this.logger.debug('Token decoded.', {tokens});
            return new SuccessResponse(res, tokens).send();
        } catch (e) {
            if (e.name === 'TokenExpiredError') {
                this.logger.warn('Token expired.', e);
                return new TokenExpiredResponse(res, 'refreshToken').send();
            } else if (e.name === 'JsonWebTokenError') {
                this.logger.warn('Token invalid.', e);
                return new InvalidTokenResponse(res, '').send();
            } else if (e.name === 'NotBeforeError') {
                this.logger.warn('Token not before.', e);
                return new TokenNotBeforeResponse(res, 'refreshToken').send();
            }
            this.logger.error('Token decoding failed.', e);
            throw e;
        }
    }

    private routes() {
        try {
            this.router.post('/password',
                this.vl.schema({
                    email: {
                        in: ['body'],
                        errorMessage: 'InvalidEmail',
                        isEmail: {}
                    },
                    password: {
                        in: ['body'],
                        errorMessage: 'InvalidPassword',
                        isLength: {
                            options: {
                                min: 8,
                                max: 40
                            }
                        }
                    },
                    atExpiresIn: {
                        in: ['body'],
                        custom: {
                            options: this.vl.isMsValue.bind(this.vl)
                        }
                    },
                    rtExpiresIn: {
                        in: ['body'],
                        custom: {
                            options: this.vl.isMsValue.bind(this.vl)
                        }
                    }
                }),
                this.vl.validate.bind(this.vl),
                (req, res, next) => this.password(req, res).catch(err => next(err))
            );

            this.router.post('/verify',
                this.vl.schema({
                    token: {
                        in: ['body'],
                        errorMessage: 'required'
                    }
                }),
                this.vl.validate.bind(this.vl),
                (req, res, next) => this.verify(req, res).catch(err => next(err))
            );

            this.router.post('/refresh',
                this.vl.schema({
                    accessToken: {
                        in: ['body'],
                        errorMessage: 'required',
                        isString: true,
                        isLength: {
                            options: {
                                min: 100,
                                max: 300
                            }
                        }
                    },
                    refreshToken: {
                        in: ['body'],
                        errorMessage: 'required',
                        isString: true,
                        isLength: {
                            options: {
                                min: 100,
                                max: 300
                            }
                        }
                    },
                    atExpiresIn: {
                        in: ['body'],
                        custom: {
                            options: this.vl.isMsValue.bind(this.vl)
                        }
                    },
                    rtExpiresIn: {
                        in: ['body'],
                        custom: {
                            options: this.vl.isMsValue.bind(this.vl)
                        }
                    }
                }),
                this.vl.validate.bind(this.vl),
                (req, res, next) => this.refresh(req, res).catch(err => next(err))
            );

        } catch (err) {
            this.logger.error('Route configuration failed.', err);
            throw err;
        }
    }
}
