export class APIError extends Error {

    public name = 'APIError';

    constructor(message?: string) {
        super(message);
    }
}

export interface IAPIError {
    message: string;
    locations: Array<{ line: number, column: number }>;
}
