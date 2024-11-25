import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { AuthenticationError, AuthorizationError } from '../utils/errors.util';
import { redisService } from '../config/redis';
import { db } from '../config/database';
import { UserRole } from '../types/enums';
import { ITokenPayload } from '../types/auth.types';

declare global {
    namespace Express {
        interface Request {
            user?: ITokenPayload;
        }
    }
}

export const authMiddleware = {
    // Verify JWT token
    verifyToken: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader?.startsWith('Bearer ')) {
                throw new AuthenticationError('No token provided');
            }

            const token = authHeader.split(' ')[1];

            // Check if token is blacklisted
            const isBlacklisted = await redisService.get(`blacklist:${token}`);
            if (isBlacklisted) {
                throw new AuthenticationError('Token is invalid');
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRET!) as ITokenPayload;

            // Verify if user still exists and is active
            const user = await db.prisma.user.findUnique({
                where: { id: decoded.userId },
                select: { id: true, role: true, isEmailVerified: true },
            });

            if (!user) {
                throw new AuthenticationError('User no longer exists');
            }

            if (!user.isEmailVerified) {
                throw new AuthenticationError('Email not verified');
            }

            req.user = decoded;
            next();
        } catch (error) {
            if (error instanceof jwt.JsonWebTokenError) {
                throw new AuthenticationError('Invalid token');
            }
            throw error;
        }
    },

    // Verify refresh token
    verifyRefreshToken: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { refreshToken } = req.body;
            if (!refreshToken) {
                throw new AuthenticationError('No refresh token provided');
            }

            // Verify token in database
            const storedToken = await db.prisma.refreshToken.findUnique({
                where: { token: refreshToken },
                include: { user: true },
            });

            if (!storedToken || storedToken.expiresAt < new Date()) {
                throw new AuthenticationError('Invalid refresh token');
            }

            const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET!) as ITokenPayload;
            req.user = decoded;
            next();
        } catch (error) {
            if (error instanceof jwt.JsonWebTokenError) {
                throw new AuthenticationError('Invalid refresh token');
            }
            throw error;
        }
    },

    // Role-based authorization
    requireRoles: (roles: UserRole[]) => {
        return (req: Request, res: Response, next: NextFunction) => {
            if (!req.user) {
                throw new AuthenticationError('User not authenticated');
            }

            if (!roles.includes(req.user.role)) {
                throw new AuthorizationError('Insufficient permissions');
            }

            next();
        };
    },

    // 2FA verification
    verify2FA: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const user = await db.prisma.user.findUnique({
                where: { id: req.user?.userId },
                select: { isTwoFactorEnabled: true },
            });

            if (user?.isTwoFactorEnabled) {
                const { twoFactorToken } = req.body;
                if (!twoFactorToken) {
                    throw new AuthenticationError('2FA token required');
                }

                const isValid = await redisService.get(`2fa:${req.user?.userId}:${twoFactorToken}`);
                if (!isValid) {
                    throw new AuthenticationError('Invalid 2FA token');
                }

                await redisService.del(`2fa:${req.user?.userId}:${twoFactorToken}`);
            }

            next();
        } catch (error) {
            next(error);
        }
    },
};