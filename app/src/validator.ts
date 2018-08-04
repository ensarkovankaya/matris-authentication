import { NextFunction, Request, Response } from 'express';
import { checkSchema, ValidationChain, validationResult, ValidationSchema } from 'express-validator/check';
import { Location } from 'express-validator/check/location';
import { matchedData, MatchedDataOptions } from 'express-validator/filter';
import { Logger } from 'matris-logger';
import { Service } from 'typedi';
import { rootLogger } from './logger';
import { ErrorResponse, IValidationError, ServerErrorResponse } from './response';

@Service()
export class RequestValidator {
    private logger: Logger;

    constructor() {
        this.logger = rootLogger.getLogger('RequestValidator');
    }

    /**
     * Checks request has validation errors if has return ErrorResponse.
     * @param {Request} req
     * @param {Response} res
     * @param {NextFunction} next
     */
    public validate(req: Request, res: Response, next: NextFunction) {
        try {
            this.logger.debug('Validating request');
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                this.logger.warn('Validation return errors', {validationErrors: errors.array()});
                return new ErrorResponse(res, errors.array() as IValidationError[]).send();
            }
            return next();
        } catch (err) {
            this.logger.error('Validation failed', err);
            return new ServerErrorResponse(res).send();
        }
    }

    /**
     * Gets matchad data from Request
     * @param {Request} req
     * @param {Location[]} locations
     * @param {boolean} onlyValidData: Default true.
     * @param {boolean} includeOptionals: Default true.
     */
    public data<T>(req: Request,
                   locations: Location[], onlyValidData: boolean = true, includeOptionals: boolean = true): T {
        return matchedData(req, {
            locations,
            onlyValidData,
            includeOptionals
        }) as T;
    }

    public schema(schema: ValidationSchema): ValidationChain[] {
        return checkSchema(schema);
    }
}
