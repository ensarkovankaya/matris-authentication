import { decode, DecodeOptions, sign, SignOptions, verify, VerifyOptions } from 'jsonwebtoken';
import { Logger } from "matris-logger";
import * as ms from 'ms';
import { Service } from 'typedi';
import { SecretUndefined, TokensNotMatched } from '../errors';
import { rootLogger } from '../logger';
import { Role } from '../models/role.model';
import { IAccessTokenPayload, IAuthToken, IDecodedTokenModel, IRefreshTokenPayload } from '../models/token.model';

export interface IOptionOverwrites {
    expiresIn?: number;
}

export interface IJWTOptions extends IOptionOverwrites {
    secret?: string;
}

/**
 * Handles Authentication related tasks.
 *
 * This service uses jsonwebtoken
 * {@link https://github.com/auth0/node-jsonwebtoken}
 */
@Service()
export class AuthenticationService {
    public secret: string;

    private logger: Logger;

    constructor(options: IJWTOptions = {}) {
        this.logger = rootLogger.getLogger('JWTService', ['service']);
        this.configure(options);
    }

    public configure(options: IJWTOptions) {
        if (options.secret) {
            this.secret = options.secret;
        }
    }

    /**
     * Authenticate users and generate access and refresh token
     * @param {string} id: User id
     * @param {Role} role: User role
     * @param {number | string} accessTokenExpiresIn: Access token life time
     * @param {number | string} refreshTokenExpiresIn: Refresh token life time
     * @param {any} data: Aditional data
     */
    public async authenticate(id: string, role: Role, accessTokenExpiresIn: number | string,
                              refreshTokenExpiresIn: number | string, data?: any): Promise<IAuthToken> {
        this.logger.debug('Genareting auth tokens', {id, role, accessTokenExpiresIn, refreshTokenExpiresIn});
        try {
            // Generate jit for access token
            const jit =  this.generateID(24);

            // Create access and refresh tokens
            const [accessToken, refreshToken] = await Promise.all([
                this.generateAccessToken(jit, id, role, accessTokenExpiresIn, data),
                this.generateRefreshToken(jit, accessTokenExpiresIn, refreshTokenExpiresIn)
            ]);

            // Decode tokens for extracting payload exp and nbf
            const [decodedAccessToken, decodedRefreshToken] = await Promise.all([
                this.decode<IDecodedTokenModel<IAccessTokenPayload>>(accessToken),
                this.decode<IDecodedTokenModel<IRefreshTokenPayload>>(refreshToken)
            ]);

            // Return tokens
            return {
                accessToken: {
                    token: accessToken,
                    tokenType: 'Bearer',
                    expiresAt: decodedAccessToken.payload.exp
                },
                refreshToken: {
                    tokenType: 'Bearer',
                    token: refreshToken,
                    notBefore: decodedRefreshToken.payload.nbf,
                    expiresAt: decodedRefreshToken.payload.exp
                }
            };
        } catch (e) {
            this.logger.error('Genareting tokens failed', e);
            throw e;
        }
    }

    /**
     * Returns new access and refresh token if given tokens are valid and match
     * @param {string} accessToken: Access token
     * @param {string} refreshToken: Refresh token
     * @param {number | string} accessTokenExpiresIn: New access token life time
     * @param {number | string} refreshTokenExpiresIn: New refresh token life time
     */
    public async refresh(accessToken: string, refreshToken: string, accessTokenExpiresIn: number | string,
                         refreshTokenExpiresIn: number | string) {
        this.logger.debug('Refreshing tokens', {
            accessToken, refreshToken,
            accessTokenExpiresIn, refreshTokenExpiresIn
        });

        // Verify tokens
        const [accessTokenPayload, refreshTokenPayload] = await Promise.all([
            this.verify<IAccessTokenPayload>(accessToken, {ignoreExpiration: true}),
            this.verify<IRefreshTokenPayload>(refreshToken)
        ]);

        // Check refresh token is related the access token
        if (accessTokenPayload.jti !== refreshTokenPayload.sub) {
            throw new TokensNotMatched();
        }

        // Return new token
        return this.authenticate(
            accessTokenPayload.sub,
            accessTokenPayload.aud,
            accessTokenExpiresIn,
            refreshTokenExpiresIn,
            accessTokenPayload.data
        );
    }

    /**
     * Generates Access Token
     * @param {string} jwtid: Unique identifier for token. This id will used in process of refreshing token.
     * @param {string} subject: User unique id.
     * @param {string | number} audience: User role.
     * @param {string | number} expiresIn: How long this token will live.
     * @param {any} data: Aditional data. This payload will add under data key
     */
    public async generateAccessToken(jwtid: string, subject: string, audience: string,
                                     expiresIn: string | number, data?: any): Promise<string> {
            this.logger.debug('Genareting access token', {jwtid, subject, audience, expiresIn, data});
            try {
                const payload = data ? {data} : {};
                return await this.sign(payload, {jwtid, subject, audience, expiresIn});
            } catch (e) {
                this.logger.error('Genareting access token failed', e);
                throw e;
            }
    }

    /**
     * Generates refresh token
     * @param {string} id: Access token jit (JWT id)
     * @param {string | number} acExpiresIn: Access token expires in.
     * @param {string | number} rtExpiresIn: Refresh token expires in.
     */
    public async generateRefreshToken(id: string, atExpiresIn: string | number,
                                      rtExpiresIn: number | string): Promise<string> {
        this.logger.debug('Genareting refresh token', {id, atExpiresIn, rtExpiresIn});
        try {
            const notBefore = typeof atExpiresIn === 'string' ? ms(atExpiresIn) : atExpiresIn;
            const expiresIn = notBefore + (typeof rtExpiresIn === 'string' ? ms(rtExpiresIn) : rtExpiresIn);
            return await this.sign({}, {notBefore, subject: id, expiresIn});
        } catch (e) {
            this.logger.error('Genareting refresh token failed', e);
            throw e;
        }
    }

    /**
     * Sign payload and returns JWT.
     * @param {object} payload User unique id
     * @returns {Promise<string>}: JWT
     */
    public async sign(payload: object, options: SignOptions = {}): Promise<string> {
        this.logger.debug('Signing payload', {payload, options});
        if (!this.secret) {
            throw new SecretUndefined();
        }
        try {
            return await new Promise<string>((resolve, reject) => {
                sign(payload, this.secret, options, (err, token) => err ? reject(err) : resolve(token));
            });
        } catch (e) {
            this.logger.error('Signing failed', e);
            throw e;
        }
    }

    /**
     * Verifies the token
     * @param token: JWT
     * @param {VerifyOptions} options
     * @returns {Promise<T>} decoded token
     */
    public async verify<T>(token: string, options: VerifyOptions = {}): Promise<T> {
        this.logger.debug('Verifing token', {token});
        if (!this.secret) {
            throw new SecretUndefined();
        }
        try {
            return await new Promise<T>((resolve, reject) => {
                verify(token, this.secret, options, (err, decoded) => err ? reject(err) : resolve(decoded as any));
            });
        } catch (err) {
            this.logger.error('Verification failed', err);
            throw err;
        }
    }

    /**
     * Only decodes the token, NOT verifies signature!
     * @param {string} token: JWT
     * @param {DecodeOptions} overwrite: Default {json: true, complete: true}
     * @returns {Promise<T>}
     */
    public async decode<T>(token: string, overwrite: DecodeOptions = {}): Promise<T> {
        this.logger.debug('Decodeding token', {token});
        try {
            return await new Promise<T>((resolve, reject) => {
                try {
                     const decoded = decode(token, {json: true, complete: true, ...overwrite}) as T;
                     resolve(decoded);
                } catch (e) {
                    reject(e);
                }
            });
        } catch (err) {
            this.logger.error('Decoding failed', err);
            throw err;
        }
    }

    public generateID(length: number): string {
        this.logger.debug('Generating id', {length});
        try {
            let id: string = '';
            while (id.length < length) {
                id += Math.random().toString(36).substr(2, 9);
            }
            return id.slice(0, length);
        } catch (e) {
            this.logger.error('Generating id failed', e);
            throw e;
        }
    }
}
