export class EnvironmentError extends Error {
    public name = 'EnvironmentError';

    constructor(public variable?: string) {
        super(`Environment variable '${variable}' required.`);
    }
}
