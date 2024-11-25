import winston from 'winston';
import path from 'path';

const logLevels = {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    debug: 4,
};

const logColors = {
    error: 'red',
    warn: 'yellow',
    info: 'green',
    http: 'magenta',
    debug: 'white',
};

winston.addColors(logColors);

const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.colorize({ all: true }),
    winston.format.printf(
        ({ timestamp, level, message, stack }) =>
            `${timestamp} ${level}: ${message}${stack ? '\n' + stack : ''}`
    )
);

const logger = winston.createLogger({
    levels: logLevels,
    level: process.env.NODE_ENV === 'development' ? 'debug' : 'info',
    format: logFormat,
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({
            filename: path.join(__dirname, '../../logs/error.log'),
            level: 'error',
        }),
        new winston.transports.File({
            filename: path.join(__dirname, '../../logs/combined.log'),
        }),
    ],
});

export { logger };