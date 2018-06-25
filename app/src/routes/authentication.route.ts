import { NextFunction, Request, Response, Router } from 'express';
import { checkSchema, validationResult } from 'express-validator/check';
import { matchedData } from 'express-validator/filter';
import { sign } from 'jsonwebtoken';
import { Container, Service } from 'typedi';
import { IAccountModel } from '../models/account.model';
import { ErrorResponse, IValidationError, ServerErrorResponse, SuccessResponse } from '../response';
import { UserService } from '../services/user.service';

@Service()
class AuthenticationRoute {

    private static validate(req: Request, res: Response, next: NextFunction) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return new ErrorResponse(res, errors.array() as IValidationError[]).send();
            }
            return next();
        } catch (err) {
            return new ServerErrorResponse(res).send();
        }
    }

    private static sign(user: IAccountModel) {
        const secret = process.env.SECRET;
        if (!secret) {
            throw new Error('SecretNotFound');
        }
        return sign({id: user._id, email: user.email, role: user.role}, secret);
    }

    public router: Router;

    constructor(private us: UserService) {
        this.router = Router({caseSensitive: true});
        this.routes();
    }

    public async authenticate(req: Request, res: Response) {
        try {
            const data = matchedData(req, {locations: ['body']}) as { email: string, password: string };
            const user = await this.us.getUserByEmail(data.email);
            if (!user) {
                return new ErrorResponse(res, [{
                    msg: 'UserNotFound',
                    location: 'body',
                    param: 'email'
                }]).send();
            }
            const valid = await this.us.isPasswordValid(data.email, data.password);
            if (!valid) {
                return new ErrorResponse(res, [{
                    msg: 'InvalidPassword',
                    location: 'body',
                    param: 'password'
                }]).send();
            }
            const token = AuthenticationRoute.sign(user);
            return new SuccessResponse(res, token).send();
        } catch (err) {
            console.error('AuthenticationRoute:Authenticate', err);
            return new ServerErrorResponse(res).send();
        }
    }

    private routes() {
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
            AuthenticationRoute.validate,
            this.authenticate.bind(this));
    }
}

export default Container.get<AuthenticationRoute>(AuthenticationRoute).router;
