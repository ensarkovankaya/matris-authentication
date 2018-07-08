export const isTest = (): boolean => process.env.NODE_ENV.toLowerCase() === 'test';

export const isDevelopment = (): boolean => {
    const env = process.env.NODE_ENV.toLowerCase();
    return env === 'dev' || env === 'development';
};
