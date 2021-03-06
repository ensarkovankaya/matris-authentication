import { NextFunction, Request, Response } from 'express';
import { checkSchema, ValidationChain, validationResult, ValidationSchema } from 'express-validator/check';
import { Location } from 'express-validator/check/location';
import { matchedData } from 'express-validator/filter';
import { Logger } from 'matris-logger';
import * as ms from 'ms';
import { Service } from 'typedi';
import { NotMSValue } from '../errors';
import { rootLogger } from '../logger';
import { ErrorResponse, IValidationError, ServerErrorResponse } from '../response';

@Service()
export class RequestValidatorService {
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
        this.logger.debug('Data extracting', {locations, onlyValidData, includeOptionals});
        try {
            const data = matchedData(req, {
                locations,
                onlyValidData,
                includeOptionals
            }) as T;
            this.logger.debug('Data extracted', data);
            return data;
        } catch (e) {
            this.logger.error('Data extraction from request failed', e);
            throw e;
        }
    }

    /**
     * Generates a validation chain with given schema
     * @param {ValidationSchema} schema
     * @returns {ValidationChain[]}
     */
    public schema(schema: ValidationSchema): ValidationChain[] {
        return checkSchema(schema);
    }

    /**
     * Checks is given value is convertable by ms library
     * @param {any} value
     * @returns {any} value
     */
    public isMsValue(value: any): any {
        try {
            this.logger.debug('IsMSValue', {value});
            if (ms(value) === undefined) {
                throw new Error();
            }
            return value;
        } catch (e) {
            throw new NotMSValue();
        }
    }
}
