import { NextFunction, Request, Response, Router } from 'express';
import { checkSchema, validationResult } from 'express-validator/check';
import { matchedData } from 'express-validator/filter';
import { Container, Service } from 'typedi';
import { IValidationError } from '../models/response.model';
import { ErrorResponse, ServerErrorResponse, SuccessResponse } from '../response';
import { UserService } from '../services/user.service';

@Service()
class AuthenticationRoute {

    public router: Router;

    constructor(private us: UserService) {
        this.router = Router({caseSensitive: true});
        this.routes();
    }

    private routes() {
        this.router.post('/authenticate',
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
            this.validate,
            this.authenticate.bind(this))
    }

    private validate(req: Request, res: Response, next: NextFunction) {
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

    public async authenticate(req: Request, res: Response) {
        try {
            const data = matchedData(req, {locations: ['body']}) as { email: string, password: string };
            const response = await this.us.getUserByEmail(data.email);
            return new SuccessResponse(res, response).send();
        } catch (err) {
            console.error('AuthenticationRoute:Authenticate', err);
            return new ServerErrorResponse(res).send();
        }
    }
}

export default Container.get<AuthenticationRoute>(AuthenticationRoute).router;
