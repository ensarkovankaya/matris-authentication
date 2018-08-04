export class EnvironmentError extends Error {
    public name = 'EnvironmentError';

    constructor(public variable?: string) {
        super(`Environment variable '${variable}' required.`);
    }
}

export class InvalidData extends Error {
    public name = 'InvalidData';
}
