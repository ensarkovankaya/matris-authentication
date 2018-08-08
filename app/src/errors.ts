export class EnvironmentError extends Error {
    public name = 'EnvironmentError';

    constructor(public variable?: string) {
        super(`Environment variable '${variable}' required.`);
    }
}

export class InvalidData extends Error {
    public name = 'InvalidData';
}

export class SecretUndefined extends Error {
    public name = 'SecretUndefined';
}

export class TokensNotMatched extends Error {
    public name = 'TokensNotMatched';
}

export class NotMSValue extends Error {
    public name = 'NotMSValue';
    public message = 'NotMSValue';
}
