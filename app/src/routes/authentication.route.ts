import { Request, Response, Router } from 'express';
import { sign } from 'jsonwebtoken';
import { AccountService } from 'matris-account-api';
import { Logger } from 'matris-logger/dist/logger';
import { Service } from 'typedi';
import { EndpointUndefined, SecretUndefined } from '../errors';
import { rootLogger } from '../logger';
import { Role } from '../models/role.model';
import {
    InvalidPasswordResponse,
    ServerErrorResponse,
    SuccessResponse,
    UserNotActiveResponse,
    UserNotFoundResponse
} from '../response';
import { RequestValidator } from '../validator';

@Service()
export class AuthenticationRoute {

    public router: Router;
    private logger: Logger;
    private secret: string;

    constructor(private ac: AccountService, private vl: RequestValidator) {
        this.logger = rootLogger.getLogger('AuthenticationRoute', ['route']);
        this.router = Router({caseSensitive: true});
        this.configure();
        this.routes();
    }

    public configure() {
        // Configure Account Service
        const endpoint = process.env.ACCOUNT_SERVICE;
        if (!endpoint) {
            throw new EndpointUndefined();
        }
        this.ac.configure({url: endpoint});

        // Check secret
        this.secret = process.env.SECRET;
        if (!this.secret) {
            throw new SecretUndefined();
        }
    }

    /**
     * Authenticate user with email and password
     * @param {Request} req
     * @param {Response} res
     */
    public async password(req: Request, res: Response) {
        // Get data from request
        let data;
        try {
            data = this.vl.data<{ email: string, password: string }>(req, ['body']);
            this.logger.debug('Data extracted from request.', {data});
        } catch (e) {
            this.logger.error('Authenticate', e);
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
            const token = this.sign(user.id, user.email, user.role);
            this.logger.debug('User data signed.', {token});
            return new SuccessResponse(res, token).send();
        } catch (e) {
            this.logger.error('Signing user data failed.', e);
            return new ServerErrorResponse(res).send();
        }
    }

    /**
     * Sign user and returns jwt.
     * @param {string} id User unique id
     * @param {string} email User email
     * @param {Role} role User role
     */
    public sign(id: string, email: string, role: Role) {
        this.logger.debug('Sign', {id, email, role});
        try {
            return sign({id, email, role}, this.secret);
        } catch (err) {
            this.logger.error('Sign', err);
            throw err;
        }
    }

    private routes() {
        try {
            this.router.post('/password',
                this.vl.schema({
                    email: {
                        in: ['body'],
                        errorMessage: 'InvalidEmail',
                        isEmail: true
                    },
                    password: {
                        in: ['body'],
                        isLength: {
                            errorMessage: 'InvalidLength',
                            options: {
                                min: 8,
                                max: 40
                            }
                        }
                    }
                }),
                this.vl.validate.bind(this.vl),
                this.password.bind(this)
            );
        } catch (err) {
            this.logger.error('Route configuration failed.', err);
            throw err;
        }
    }
}
