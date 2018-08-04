import { Request, Response, Router } from 'express';
import { AccountService } from 'matris-account-api';
import { Logger } from 'matris-logger/dist/logger';
import { Service } from 'typedi';
import { EnvironmentError, InvalidData } from '../errors';
import { rootLogger } from '../logger';
import { IDecodedTokenModel } from '../models/decoded.token.model';
import {
    InvalidPasswordResponse,
    ServerErrorResponse,
    SuccessResponse,
    TokenExpiredResponse,
    UserNotActiveResponse,
    UserNotFoundResponse
} from '../response';
import { InvalidTokenResponse } from '../response';
import { JWTService } from '../services/jwt.service';
import { RequestValidator } from '../validator';

@Service()
export class AuthenticationRoute {

    public router: Router;
    private logger: Logger;

    constructor(private ac: AccountService, private vl: RequestValidator, private jwt: JWTService) {
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

        const expiresIn = process.env.JWT_EXPIRES_IN;
        if (!expiresIn) {
            throw new EnvironmentError('JWT_EXPIRES_IN');
        }

        // Configure JWT Service
        this.jwt.configure({expiresIn, secret});
    }

    /**
     * Authenticate user with email and password
     * @param {Request} req
     * @param {Response} res
     */
    public async password(req: Request, res: Response) {
        // Get data from request
        let data: { email: string, password: string, expiresIn?: number };
        try {
            data = this.vl.data<{ email: string, password: string, expiresIn?: number }>(req, ['body']);
            this.logger.debug('Data extracted from request.', {data});
            if (!data || !data.email || !data.password) {
                throw new InvalidData();
            }
        } catch (e) {
            this.logger.error('Data extraction from request failed', e);
            return new ServerErrorResponse(res).send();
        }

        // Get user from AccountService
        let user;
        try {
            user = await this.ac.get({email: data.email}, ['_id', 'email', 'role', 'active']);
            this.logger.debug('User recived.', {user});
        } catch (e) {
            this.logger.error('Getting user from AccountService failed.', e);
            return new ServerErrorResponse(res).send();
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
            return new ServerErrorResponse(res).send();
        }

        // If password not valid return InvalidPasswordResponse
        if (!valid) {
            return new InvalidPasswordResponse(res).send();
        }

        try {
            // Sign
            const options = data.expiresIn !== undefined ? {expiresIn: data.expiresIn} : {};
            const token = await this.jwt.sign({id: user.id, email: user.email, role: user.role}, options);
            this.logger.debug('User data signed.', {token});
            return new SuccessResponse(res, token).send();
        } catch (e) {
            this.logger.error('Signing user data failed.', e);
            return new ServerErrorResponse(res).send();
        }
    }

    /**
     * Validates jwt token if token valid returns decoded token.
     * If token expired returns TokenExpiredResponse
     * If token invalid returns InvalidTokenResponse
     * @param {Request} req
     * @param {Response} res
     */
    public async validate(req: Request, res: Response) {
        // Get data from request
        let data: {token: string};
        try {
            data = this.vl.data<{ token: string }>(req, ['body']);
            this.logger.debug('Data extracted from request.', {data});

            if (!data || !data.token) {
                throw new InvalidData();
            }
        } catch (e) {
            this.logger.error('Data extraction from request failed', e);
            return new ServerErrorResponse(res).send();
        }

        try {
            // Decode Token
            const decoded = await this.jwt.verify<IDecodedTokenModel>(data.token);
            this.logger.debug('Token decoded.', {decoded});
            return new SuccessResponse(res, decoded).send();
        } catch (e) {
            if (e.name === 'TokenExpiredError') {
                this.logger.warn('Token expired.', e);
                return new TokenExpiredResponse(res).send();
            } else if (e.name === 'JsonWebTokenError') {
                this.logger.warn('Token invalid.', e);
                return new InvalidTokenResponse(res).send();
            }
            this.logger.error('Token decoding failed.', e);
            return new ServerErrorResponse(res).send();
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
                    expiresIn: {
                        in: ['body'],
                        optional: {},
                        isNumeric: {
                            options: {
                                min: 0,
                                max: 60 * 60 * 24 * 30 // 1 month
                            }
                        },
                        toInt: {}
                    }
                }),
                this.vl.validate.bind(this.vl),
                this.password.bind(this)
            );

            this.router.post('/verify',
                this.vl.schema({
                    token: {
                        in: ['body'],
                        errorMessage: 'InvalidToken',
                        isString: {},
                        isLength: {
                            options: {
                                min: 200
                            }
                        }
                    }
                }),
                this.vl.validate.bind(this.vl),
                this.validate.bind(this)
            );
        } catch (err) {
            this.logger.error('Route configuration failed.', err);
            throw err;
        }
    }
}
