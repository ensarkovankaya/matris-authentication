import { decode, sign } from 'jsonwebtoken';
import { IAccessTokenPayload, IDecodedTokenModel, IRefreshTokenPayload } from '../../../src/models/token.model';
import { Database } from '../valid/database';
import { IDBUserModel } from '../valid/db.model';
import { IAuthToken } from './models';

const genereateID = (length: number): string => {
    let id: string = '';
    while (id.length < length) {
        id += Math.random().toString(36).substr(2, 9);
    }
    return id.slice(0, length);
};

/**
 * Generates Access-Refresh Token pares for testing
 */
export class RefreshTokenGenerator {

    private db: Database;

    constructor(public secret: string) {
        this.db = new Database();
    }

    public async one(): Promise<IAuthToken> {
        return this.generate(this.db.one(u => u.active === true && u.deleted === false));
    }

    public async multiple(limit: number): Promise<IAuthToken[]> {
        const users = this.db.multiple(limit, u => u.active === true && u.deleted === false);
        return await Promise.all(users.map(u => this.generate(u)));
    }

    private async generate(user: IDBUserModel): Promise<IAuthToken> {
        const jwtid = genereateID(24);

        const accessToken: string = await new Promise<string>((resolve, reject) => {
            sign({}, this.secret, {
                jwtid,
                subject: user._id,
                audience: user.role,
                expiresIn: '1ms'
            },
                (err, tkn) => err ? reject(err) : resolve(tkn)
            );
        });

        const accessDecoded = await new Promise<IDecodedTokenModel<IAccessTokenPayload>>((resolve, reject) => {
            try {
                resolve(decode(accessToken, {json: true, complete: true}) as IDecodedTokenModel<IAccessTokenPayload>);
            } catch (e) {
                reject(e);
            }
        });

        const refreshToken: string = await new Promise<string>((resolve, reject) => {
            sign({}, this.secret, {
                subject: jwtid,
                notBefore: '1ms',
                expiresIn: '10s'
            },
                (err, tkn) => err ? reject(err) : resolve(tkn)
            );
        });

        const refreshDecoded = await new Promise<IDecodedTokenModel<IRefreshTokenPayload>>((resolve, reject) => {
            try {
                resolve(decode(refreshToken, {json: true, complete: true}) as IDecodedTokenModel<IRefreshTokenPayload>);
            } catch (e) {
                reject(e);
            }
        });

        return {
            accessToken,
            accessDecoded,
            refreshToken,
            refreshDecoded
        };
    }
}
