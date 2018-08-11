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
    accessDecoded: IDecodedToken<{
        iat: number;
        exp: number;
        aud: string;
        sub: string;
        jti: string;
    }>;
    refreshToken: string;
    refreshDecoded: IDecodedToken<{
        iat: number;
        nbf: number;
        exp: number;
        sub: string;
    }>;
}
