import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import rateLimit, { ClientRateLimitInfo } from 'express-rate-limit';
import { redisService } from '../config/redis';
import { logger } from '../config/logger';
import { AuthenticationError } from '../utils/errors.util';

// Rate limiting with Redis
const createRateLimiter = (windowMs: number, max: number, keyPrefix: string) => {
    return rateLimit({
        windowMs,
        max,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: (req: Request) => `${keyPrefix}:${req.ip}`,
        handler: (req: Request, res: Response) => {
            throw new AuthenticationError('Too many requests. Please try again later.');
        },
        store: {
            init: () => {
                logger.info('Rate limiter initialized with Redis store');
            },
            increment: async (key: string): Promise<ClientRateLimitInfo> => {
                const count = await redisService.client.incr(key);
                await redisService.client.expire(key, windowMs / 1000);
                return {
                    totalHits: count,
                    resetTime: new Date(Date.now() + windowMs)
                };
            },
            decrement: async (key: string) => {
                await redisService.client.decr(key);
            },
            resetKey: async (key: string) => {
                await redisService.client.del(key);
            },
        },
    });
};

export const securityMiddleware = {
    // Basic security headers
    basicSecurity: helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", 'data:', 'https:'],
            },
        },
        referrerPolicy: { policy: 'same-origin' },
    }),

    // Rate limiters
    globalRateLimit: createRateLimiter(
        15 * 60 * 1000, // 15 minutes
        100, // 100 requests
        'global'
    ),

    authRateLimit: createRateLimiter(
        15 * 60 * 1000, // 15 minutes
        5, // 5 attempts
        'auth'
    ),

    // Rest of the middleware remains the same...
    corsOptions: {
        origin: (origin: string | undefined, callback: (error: Error | null, allow?: boolean) => void) => {
            const allowedOrigins = (process.env.CORS_ORIGIN || '').split(',');
            if (!origin || allowedOrigins.includes(origin)) {
                callback(null, true);
            } else {
                callback(new Error('Not allowed by CORS'));
            }
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        maxAge: 86400, // 24 hours
    },

    sanitizeRequest: (req: Request, res: Response, next: NextFunction) => {
        const sanitize = (obj: any): any => {
            if (!obj) return obj;

            if (Array.isArray(obj)) {
                return obj.map(sanitize);
            }

            if (typeof obj === 'object') {
                const sanitized: any = {};
                for (const [key, value] of Object.entries(obj)) {
                    sanitized[key] = sanitize(value);
                }
                return sanitized;
            }

            if (typeof obj === 'string') {
                return obj
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#x27;')
                    .replace(/\//g, '&#x2F;');
            }

            return obj;
        };

        req.body = sanitize(req.body);
        req.query = sanitize(req.query);
        req.params = sanitize(req.params);

        next();
    },

    validateContentType: (req: Request, res: Response, next: NextFunction) => {
        if (req.method === 'POST' || req.method === 'PUT') {
            if (!req.is('application/json')) {
                throw new Error('Content-Type must be application/json');
            }
        }
        next();
    },
};