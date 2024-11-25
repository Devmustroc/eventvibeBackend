import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../services/auth.service';
import { validate } from '../utils/validation.util';
import {
    loginSchema,
    refreshTokenSchema,
    registrationSchema
} from '../utils/validation.util';
import { logger } from '../config/logger';
import { AuthenticationError } from '../utils/errors.util';
import { ILoginCredentials, IUserCreate } from '../types/auth.types';

export class AuthController {
    private static instance: AuthController;
    private authService: AuthService;

    private constructor() {
        this.authService = AuthService.getInstance();
    }

    public static getInstance(): AuthController {
        if (!AuthController.instance) {
            AuthController.instance = new AuthController();
        }
        return AuthController.instance;
    }

    public register = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const validatedData = validate(registrationSchema, req.body) as IUserCreate;
            await this.authService.register(validatedData);

            res.status(201).json({
                status: 'success',
                message: 'Registration successful. Please verify your email.',
            });
        } catch (error) {
            logger.error('Registration error:', error);
            next(error);
        }
    };

    public login = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const credentials = validate(loginSchema, req.body) as ILoginCredentials;
            const { accessToken, refreshToken } = await this.authService.login(credentials);

            // Set refresh token in HTTP-only cookie
            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
                path: '/api/auth/refresh-token',
                sameSite: 'strict',
            });

            res.json({
                status: 'success',
                data: { accessToken },
            });
        } catch (error) {
            logger.error('Login error:', error);
            next(error);
        }
    };

    public refreshToken = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { refreshToken } = validate(refreshTokenSchema, {
                refreshToken: req.cookies.refreshToken,
            }) as { refreshToken: string };

            if (!refreshToken) {
                throw new AuthenticationError('Refresh token not found');
            }

            const tokens = await this.authService.refreshToken(refreshToken);

            res.cookie('refreshToken', tokens.refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                maxAge: 7 * 24 * 60 * 60 * 1000,
                path: '/api/auth/refresh-token',
                sameSite: 'strict',
            });

            res.json({
                status: 'success',
                data: { accessToken: tokens.accessToken },
            });
        } catch (error) {
            logger.error('Token refresh error:', error);
            next(error);
        }
    };

    public logout = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const token = req.headers.authorization?.split(' ')[1];
            if (!token) {
                throw new AuthenticationError('No token provided');
            }

            await this.authService.logout(token);

            res.clearCookie('refreshToken', {
                path: '/api/auth/refresh-token',
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
            });

            res.json({
                status: 'success',
                message: 'Logged out successfully',
            });
        } catch (error) {
            logger.error('Logout error:', error);
            next(error);
        }
    };

    public enable2FA = async (req: Request, res: Response, next: NextFunction) => {
        try {
            if (!req.user?.userId) {
                throw new AuthenticationError('User not authenticated');
            }

            const qrCodeUrl = await this.authService.enable2FA(req.user.userId);

            res.json({
                status: 'success',
                data: { qrCodeUrl },
            });
        } catch (error) {
            logger.error('2FA enable error:', error);
            next(error);
        }
    };

    public verify2FA = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { token } = validate(
                req.body,
                refreshTokenSchema
            ) as { token: string };

            if (!req.user?.userId) {
                throw new AuthenticationError('User not authenticated');
            }

            const isValid = await this.authService.verify2FAToken(
                req.user.userId,
                token
            );

            if (!isValid) {
                throw new AuthenticationError('Invalid 2FA token');
            }

            res.json({
                status: 'success',
                message: '2FA verification successful',
            });
        } catch (error) {
            logger.error('2FA verification error:', error);
            next(error);
        }
    };

    public verifyEmail = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const token = req.query.token as string;

            if (!token) {
                throw new AuthenticationError('Verification token is required');
            }

            await this.authService.verifyEmail(token);

            res.json({
                status: 'success',
                message: 'Email verified successfully',
            });
        } catch (error) {
            logger.error('Email verification error:', error);
            next(error);
        }
    };

    public forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { email } = validate(
                loginSchema,
                req.body
            ) as { email: string };

            await this.authService.forgotPassword(email);

            res.json({
                status: 'success',
                message: 'Password reset email sent',
            });
        } catch (error) {
            logger.error('Forgot password error:', error);
            next(error);
        }
    };

    public resetPassword = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { token, newPassword } = req.body;

            if (!token || !newPassword) {
                throw new AuthenticationError('Token and new password are required');
            }

            await this.authService.resetPassword(token, newPassword);

            res.json({
                status: 'success',
                message: 'Password reset successful',
            });
        } catch (error) {
            logger.error('Password reset error:', error);
            next(error);
        }
    };
}

export const authController = AuthController.getInstance();