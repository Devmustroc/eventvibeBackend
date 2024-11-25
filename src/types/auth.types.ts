import { UserRole } from './enums';

export interface IUserCreate {
    email: string;
    password: string;
    firstName?: string;
    lastName?: string;
    phone?: string;
}

export interface ILoginCredentials {
    email: string;
    password: string;
}

export interface ITokenPayload {
    userId: string;
    role: UserRole;
    type: 'access' | 'refresh';
}

export interface IAuthTokens {
    accessToken: string;
    refreshToken: string;
}

export interface IPasswordReset {
    token: string;
    newPassword: string;
}

export interface IEmailVerification {
    token: string;
}

export interface ITwoFactorVerification {
    token: string;
}

