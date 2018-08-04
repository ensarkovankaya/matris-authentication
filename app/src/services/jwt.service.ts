import { sign, verify } from 'jsonwebtoken';
import { Logger } from "matris-logger";
import { Service } from 'typedi';
import { rootLogger } from '../logger';

export interface IJWTOptions {
    expiresIn?: number | string;
    secret?: string;
}

@Service()
export class JWTService {
    public expiresIn: string | number;
    public secret: string;

    private logger: Logger;

    constructor(options: IJWTOptions = {}) {
        this.expiresIn = '1d';
        this.logger = rootLogger.getLogger('JWTService', ['service']);
        this.configure(options);
    }

    public configure(options: IJWTOptions) {
        if (options.expiresIn) {
            this.expiresIn = options.expiresIn;
        }
        if (options.secret) {
            this.secret = options.secret;
        }
    }

    /**
     * Sign payload and returns jwt.
     * @param {object} payload User unique id
     * @returns {Promise<string>}: token
     */
    public async sign(payload: object): Promise<string> {
        this.logger.debug('Sign', {payload});
        try {
            return await new Promise<string>((resolve, reject) => {
                const options = {expiresIn: this.expiresIn};
                sign(payload, this.secret, options, (err, token) => err ? reject(err) : resolve(token));
            });
        } catch (e) {
            this.logger.error('Sign', e);
            throw e;
        }
    }

    /**
     * Verifies the token
     * @param token: json web token
     * @returns {Promise<T>} decoded token
     */
    public async verify<T>(token: string): Promise<T> {
        this.logger.debug('Verify', {token});
        try {
            return await new Promise<T>((resolve, reject) => {
                verify(token, this.secret, (err, decoded) => err ? reject(err) : resolve(decoded as any));
            });
        } catch (err) {
            this.logger.error('Verify', err);
            throw err;
        }
    }
}
