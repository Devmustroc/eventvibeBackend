import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { authenticator } from 'otplib';
import {ITokenPayload, UserRole} from "@/types/enums";
import {IAuthTokens, ILoginCredentials, IUserCreate} from "@/types/auth.types";
import {db} from "@/config/database";
import {AuthenticationError} from "@/utils/errors.util";
import {logger} from "@/config/logger";
import {redisService} from "@/config/redis";
import {emailService} from "@/config/email";

export class AuthService {
    private static instance: AuthService;
    private readonly REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 days
    private readonly PASSWORD_RESET_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours
    private readonly TOTP_WINDOW = 1; // Time window for 2FA tokens

    private constructor() {
        authenticator.options = {
            window: this.TOTP_WINDOW,
        };
    }

    public static getInstance(): AuthService {
        if (!AuthService.instance) {
            AuthService.instance = new AuthService();
        }
        return AuthService.instance;
    }

    // Register new user
    public async register(userData: IUserCreate): Promise<void> {
        const existingUser = await db.prisma.user.findUnique({
            where: { email: userData.email },
        });

        if (existingUser) {
            throw new AuthenticationError('Email already registered');
        }

        const hashedPassword = await bcrypt.hash(userData.password, 12);
        const verificationToken = crypto.randomBytes(32).toString('hex');

        try {
            await db.prisma.user.create({
                data: {
                    ...userData,
                    password: hashedPassword,
                    verificationToken,
                },
            });

            await this.sendVerificationEmail(userData.email, verificationToken);
            logger.info(`User registered successfully: ${userData.email}`);
        } catch (error) {
            logger.error('Registration error:', error);
            throw new Error('Failed to register user');
        }
    }

    // Login user
    public async login(credentials: ILoginCredentials): Promise<IAuthTokens> {
        const user = await db.prisma.user.findUnique({
            where: { email: credentials.email },
        });

        if (!user) {
            throw new AuthenticationError('Invalid credentials');
        }

        const isPasswordValid = await bcrypt.compare(credentials.password, user.password);
        if (!isPasswordValid) {
            throw new AuthenticationError('Invalid credentials');
        }

        if (!user.isEmailVerified) {
            throw new AuthenticationError('Email not verified');
        }

        const tokens = await this.generateTokens(user.id, user.role as UserRole);

        if (user.isTwoFactorEnabled) {
            const totpToken = authenticator.generate(user.twoFactorSecret!);
            await redisService.set(
                `2fa:${user.id}:${totpToken}`,
                'valid',
                300 // 5 minutes
            );
        }

        await db.prisma.user.update({
            where: { id: user.id },
            data: { lastLogin: new Date() },
        });

        logger.info(`User logged in successfully: ${user.email}`);
        return tokens;
    }

    // Refresh token
    public async refreshToken(token: string): Promise<IAuthTokens> {
        try {
            const decodedToken = jwt.verify(
                token,
                process.env.JWT_REFRESH_SECRET!
            ) as ITokenPayload;

            const storedToken = await db.prisma.refreshToken.findFirst({
                where: {
                    token,
                    userId: decodedToken.userId,
                    expiresAt: { gt: new Date() }
                },
            });

            if (!storedToken) {
                throw new AuthenticationError('Invalid refresh token');
            }

            // Delete old refresh token
            await db.prisma.refreshToken.delete({
                where: { id: storedToken.id },
            });

            return this.generateTokens(decodedToken.userId, decodedToken.role as UserRole);
        } catch (error) {
            if (error instanceof jwt.TokenExpiredError) {
                throw new AuthenticationError('Refresh token expired');
            }
            throw error;
        }
    }

    // Generate authentication tokens
    private async generateTokens(userId: string, role: UserRole): Promise<IAuthTokens> {
        const payload: ITokenPayload = { userId, role, type: 'access' };

        const accessToken = jwt.sign(payload, process.env.JWT_SECRET!, {
            expiresIn: process.env.JWT_EXPIRES_IN,
        });

        const refreshToken = jwt.sign(
            { ...payload, type: 'refresh' },
            process.env.JWT_REFRESH_SECRET!,
            { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN }
        );

        await db.prisma.refreshToken.create({
            data: {
                token: refreshToken,
                userId,
                expiresAt: new Date(Date.now() + this.REFRESH_TOKEN_EXPIRY),
            },
        });

        return { accessToken, refreshToken };
    }

    // Enable 2FA
    public async enable2FA(userId: string): Promise<string> {
        const secret = authenticator.generateSecret();

        await db.prisma.user.update({
            where: { id: userId },
            data: {
                twoFactorSecret: secret,
                isTwoFactorEnabled: true,
            },
        });

        logger.info(`2FA enabled for user: ${userId}`);
        return authenticator.keyuri(userId, 'EventVibe', secret);
    }

    // Verify 2FA token
    public async verify2FAToken(userId: string, token: string): Promise<boolean> {
        const user = await db.prisma.user.findUnique({
            where: { id: userId },
            select: { twoFactorSecret: true },
        });

        if (!user?.twoFactorSecret) {
            throw new AuthenticationError('2FA not enabled');
        }

        return authenticator.verify({
            token,
            secret: user.twoFactorSecret,
        });
    }

    // Email verification
    public async verifyEmail(token: string): Promise<void> {
        const user = await db.prisma.user.findFirst({
            where: { verificationToken: token },
        });

        if (!user) {
            throw new AuthenticationError('Invalid verification token');
        }

        await db.prisma.user.update({
            where: { id: user.id },
            data: {
                isEmailVerified: true,
                verificationToken: null,
            },
        });

        logger.info(`Email verified for user: ${user.email}`);
    }

    // Password reset request
    public async forgotPassword(email: string): Promise<void> {
        const user = await db.prisma.user.findUnique({
            where: { email },
        });

        if (!user) {
            // Return for security (don't reveal if email exists)
            return;
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = new Date(Date.now() + this.PASSWORD_RESET_EXPIRY);

        await db.prisma.user.update({
            where: { id: user.id },
            data: {
                resetToken,
                resetTokenExpiry,
            },
        });

        await this.sendPasswordResetEmail(email, resetToken);
        logger.info(`Password reset requested for: ${email}`);
    }

    // Reset password
    public async resetPassword(token: string, newPassword: string): Promise<void> {
        const user = await db.prisma.user.findFirst({
            where: {
                resetToken: token,
                resetTokenExpiry: { gt: new Date() },
            },
        });

        if (!user) {
            throw new AuthenticationError('Invalid or expired reset token');
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);

        await db.prisma.user.update({
            where: { id: user.id },
            data: {
                password: hashedPassword,
                resetToken: null,
                resetTokenExpiry: null,
            },
        });

        // Invalidate all refresh tokens for security
        await db.prisma.refreshToken.deleteMany({
            where: { userId: user.id },
        });

        logger.info(`Password reset completed for: ${user.email}`);
    }

    // Logout user
    public async logout(token: string): Promise<void> {
        const decoded = jwt.decode(token) as jwt.JwtPayload;
        const expiresIn = decoded.exp! - Math.floor(Date.now() / 1000);

        await Promise.all([
            redisService.set(`blacklist:${token}`, 'true', expiresIn),
            db.prisma.refreshToken.deleteMany({
                where: { userId: decoded.userId },
            }),
        ]);

        logger.info(`User logged out: ${decoded.userId}`);
    }

    // Send verification email
    private async sendVerificationEmail(email: string, token: string): Promise<void> {
        const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

        await emailService.sendMail({
            to: email,
            subject: 'Verify your email address',
            html: `
                <h1>Welcome to EventVibe</h1>
                <p>Please click the button below to verify your email address:</p>
                <a href="${verificationUrl}" style="padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">
                    Verify Email
                </a>
                <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
                <p>${verificationUrl}</p>
            `,
        });
    }

    // Send password reset email
    private async sendPasswordResetEmail(email: string, token: string): Promise<void> {
        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

        await emailService.sendMail({
            to: email,
            subject: 'Reset your password',
            html: `
                <h1>Password Reset Request</h1>
                <p>You requested a password reset. Click the button below to reset your password:</p>
                <a href="${resetUrl}" style="padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">
                    Reset Password
                </a>
                <p>If you didn't request this, please ignore this email.</p>
                <p>This link will expire in 24 hours.</p>
            `,
        });
    }
}

export const authService = AuthService.getInstance();