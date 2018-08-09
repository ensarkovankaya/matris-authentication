import { Role } from './role.model';

export interface IAccessTokenPayload {
    sub: string;
    aud: Role;
    iat: number;
    exp: number;
    jti: string;
    data?: any;
}

export interface IRefreshTokenPayload {
    sub: string;
    nbf: number;
    iat: number;
    exp: number;
}

export interface IDecodedTokenModel<T> {
    header: {
        alg: string;
        typ: string;
    };
    payload: T;
    signature: string;
}

export interface IAuthToken {
    accessToken: {
        tokenType: string;
        token: string;
        expiresAt: number;
    };
    refreshToken: {
        tokenType: string;
        token: string;
        expiresAt: number;
        notBefore: number;
    };
}
