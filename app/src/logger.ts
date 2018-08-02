import { LogLevel, RootLogger } from 'matris-logger';

const level = process.env.LOG_LEVEL as LogLevel || 'info';

export const rootLogger = new RootLogger({level});
