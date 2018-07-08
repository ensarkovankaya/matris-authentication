import { NextFunction, Request, Response, Router } from 'express';
import { checkSchema, validationResult } from 'express-validator/check';
import { matchedData } from 'express-validator/filter';
import { sign } from 'jsonwebtoken';
import { Service } from 'typedi';
import { Logger } from '../logger';
import { IAccountModel } from '../models/account.model';
import { ErrorResponse, IValidationError, ServerErrorResponse, SuccessResponse } from '../response';
import { UserService } from '../services/user.service';

@Service()
export class AuthenticationRoute {

    public router: Router;
    private logger: Logger;

    constructor(private us: UserService) {
        this.logger = new Logger('AuthenticationRoute', ['route']);
        this.router = Router({caseSensitive: true});
        this.routes();
    }

    public async authenticate(req: Request, res: Response) {
        try {
            const data = matchedData(req, {locations: ['body']}) as { email: string, password: string };
            this.logger.debug('Authenticate', {data});
            const user = await this.us.getUserByEmail(data.email);
            this.logger.debug('Authenticate', {user});
            if (!user) {
                return new ErrorResponse(res, [{
                    msg: 'UserNotFound',
                    location: 'body',
                    param: 'email'
                }]).send();
            }
            const valid = await this.us.isPasswordValid(data.email, data.password);
            this.logger.debug('Authenticate', {valid});
            if (!valid) {
                return new ErrorResponse(res, [{
                    msg: 'InvalidPassword',
                    location: 'body',
                    param: 'password'
                }]).send();
            }
            const token = this.sign(user);
            this.logger.debug('Authenticate', {token});
            return new SuccessResponse(res, token).send();
        } catch (err) {
            this.logger.error('Authenticate', err);
            return new ServerErrorResponse(res).send();
        }
    }

    private routes() {
        try {
            this.router.post('/authorize',
                checkSchema({
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
                                max: 32
                            }
                        }
                    }
                }),
                this.validate.bind(this),
                this.authenticate.bind(this));
        } catch (err) {
            this.logger.error('Route configuration failed.', err);
            throw err;
        }
    }

    private sign(user: IAccountModel) {
        this.logger.debug('Sign', user);
        try {
            const secret = process.env.SECRET;
            if (!secret) {
                throw new Error('SecretNotFound');
            }
            return sign({id: user._id, email: user.email, role: user.role}, secret);
        } catch (err) {
            this.logger.error('Sign', err);
            throw err;
        }
    }

    private validate(req: Request, res: Response, next: NextFunction) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                this.logger.warn('Validate', {validationErrors: errors.array()});
                return new ErrorResponse(res, errors.array() as IValidationError[]).send();
            }
            return next();
        } catch (err) {
            this.logger.error('Validate', err);
            return new ServerErrorResponse(res).send();
        }
    }
}
