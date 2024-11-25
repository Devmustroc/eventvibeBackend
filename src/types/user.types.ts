import { User, Event } from '@prisma/client';
import {UserRole} from "@/types/enums";

export interface IUserUpdate {
    email?: string;
    password?: string;
    firstName?: string;
    lastName?: string;
    phone?: string;
    avatar?: string;
    favoriteIds?: string[];
}

export interface IUser {
    id: string;
    email: string;
    password: string;
    firstName: string | null;
    lastName: string | null;
    phone: string | null;
    avatar: string | null;
    role: UserRole;
    isEmailVerified: boolean;
    isTwoFactorEnabled: boolean;
    twoFactorSecret: string | null;
    verificationToken: string | null;
    resetToken: string | null;
    resetTokenExpiry: Date | null;
    lastLogin: Date | null;
    createdAt: Date;
    updatedAt: Date;
}

export interface IUserProfile {
    id: string;
    firstName: string | null;
    lastName: string | null;
    avatar: string | null;
    createdAt: Date;
    events: {
        id: string;
        title: string;
        imageSrc: string;  // Changed from images array
        startDate: Date;
        category: string;
    }[];
}


export interface IUserStats {
    eventsCreated: number;
    eventsAttending: number;
    totalFavorites: number;
}

export interface IUserSearchResult {
    id: string;
    firstName: string | null;
    lastName: string | null;
    avatar: string | null;
}

export interface IPaginatedResponse<T = any> {
    data: T[];
    pagination: {
        total: number;
        page: number;
        limit: number;
        totalPages: number;
    };
}

// Type guard to check if a user exists
export function isUser(user: User | null): user is User {
    return user !== null;
}

export interface IUserWithRelations extends User {
    events?: Event[];
    favorites?: Event[];
}