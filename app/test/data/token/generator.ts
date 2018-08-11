import { decode, DecodeOptions, sign, SignOptions, verify, VerifyOptions } from 'jsonwebtoken';
import * as ms from 'ms';
import { IAccessTokenPayload, IRefreshTokenPayload } from '../../../src/models/token.model';
import { Database } from '../valid/database';
import { IAuthToken } from './models';

export class TokenGenerator {
    public db: Database;

    constructor() {
        this.db = new Database();
    }

    public async authToken(secret: string, atExpiresIn: string | number,
                           rtExpiresIn: string | number, user: {_id: string, role: string}): Promise<IAuthToken> {
        const jwtid = this.generateID(24);

        const [accessToken, refreshToken] = await Promise.all([
            this.accessToken(jwtid, atExpiresIn, user._id, user.role, secret),
            this.refreshToken(jwtid, rtExpiresIn, atExpiresIn, secret)
        ]);

        const [atDecoded, rtDecoded] = await Promise.all([
            this.decode<IAccessTokenPayload>(accessToken, {}),
            this.decode<IRefreshTokenPayload>(refreshToken)
        ]);

        return {
            accessToken,
            refreshToken,
            atDecoded,
            rtDecoded
        };
    }

    public async accessToken(jwtid: string, expiresIn: string | number,
                             subject: string, audience: string, secret: string, data: object = null): Promise<string> {
        return await this.sign(data ? {data} : {}, secret, {jwtid, expiresIn, subject, audience});
    }

    public async refreshToken(jwtid: string, atExpiresIn: string | number,
                              rtExpiresIn: string | number, secret: string): Promise<string> {
        const notBefore = typeof atExpiresIn === 'string' ? ms(atExpiresIn) : atExpiresIn;
        const expiresIn = notBefore + (typeof rtExpiresIn === 'string' ? ms(rtExpiresIn) : rtExpiresIn);
        return await this.sign({}, secret, {expiresIn, subject: jwtid, notBefore});
    }

    public generateID(length: number): string {
        let id: string = '';
        while (id.length < length) {
            id += Math.random().toString(36).substr(2, 9);
        }
        return id.slice(0, length);
    }

    private async sign(paylaod: any, secret: string, options: SignOptions = {}): Promise<string> {
        return await new Promise<string>((resolve, reject) => {
            sign(paylaod, secret, options, (err, tkn) => err ? reject(err) : resolve(tkn));
        });
    }

    private async decode<T>(token: string, options: DecodeOptions = {}) {
        return await new Promise<T>((resolve, reject) => {
            try {
                resolve(decode(token, options) as T);
            } catch (e) {
                reject(e);
            }
        });
    }

    private async verify<T>(token: string, secret: string, options: VerifyOptions) {
        return await new Promise<T>((resolve, reject) => {
            verify(token, secret, options, (err, decoded) => err ? reject(err) : resolve(decoded as any));
        });
    }
}
