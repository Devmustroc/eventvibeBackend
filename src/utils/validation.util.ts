import { z } from 'zod';

export const registrationSchema = z.object({
    email: z.string().email('Invalid email address'),
    password: z.string().min(8, 'Password must be at least 8 characters'),
    firstName: z.string().min(2, 'First name must be at least 2 characters').optional(),
    lastName: z.string().min(2, 'Last name must be at least 2 characters').optional(),
    phone: z.string().regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number').optional(),
});

export const loginSchema = z.object({
    email: z.string().email('Invalid email address'),
    password: z.string().min(1, 'Password is required'),
});

export const refreshTokenSchema = z.object({
    refreshToken: z.string().min(1, 'Refresh token is required'),
});

export const twoFactorSchema = z.object({
    token: z.string().length(6, 'Token must be 6 characters'),
});

export const passwordResetSchema = z.object({
    token: z.string().min(1, 'Token is required'),
    newPassword: z.string().min(8, 'Password must be at least 8 characters'),
});

export function validate<T extends z.ZodSchema>(
    schema: T,
    data: unknown
): z.infer<T> {
    return schema.parse(data);
}

export const userUpdateSchema = z.object({
    email: z.string().email().optional(),
    firstName: z.string().min(2).max(50).optional(),
    lastName: z.string().min(2).max(50).optional(),
    phone: z.string().regex(/^\+?[1-9]\d{1,14}$/).optional(),
    password: z.string().min(8).optional(),
});
