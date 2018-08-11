import { IAccessTokenPayload, IRefreshTokenPayload } from '../../../src/models/token.model';

interface IDecodedToken<T> {
    header: {
        alg: string;
        typ: string;
    };
    payload: T;
    signature: string;
}

export interface IToken {
    token: string;
    decoded: IDecodedToken<{
        iat: number;
        exp: number;
        aud: string;
        sub: string;
        jti: string;
    }>;
    secret: string;
}

export interface IAuthToken {
    accessToken: string;
    atDecoded: IAccessTokenPayload;
    refreshToken: string;
    rtDecoded: IRefreshTokenPayload;
}
