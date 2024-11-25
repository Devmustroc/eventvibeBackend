import { User, Event } from '@prisma/client';
import bcrypt from 'bcryptjs';
import {deleteFile, uploadFile} from "@/utils/storage.utils";
import {redisService} from "@/config/redis";
import {db} from "@/config/database";
import {logger} from "@/config/logger";
import {IPaginatedResponse, IUserProfile, IUserUpdate} from "@/types/user.types";
import {AuthenticationError} from "@/utils/errors.util";
import path from "path";

export class UserService {
    private static instance: UserService;
    private readonly CACHE_TTL = 3600; // 1 hour

    private constructor() {}

    public static getInstance(): UserService {
        if (!UserService.instance) {
            UserService.instance = new UserService();
        }
        return UserService.instance;
    }

    public async getUserById(userId: string): Promise<User | null> {
        try {
            const cachedUser = await redisService.get(`user:${userId}`);
            if (cachedUser) {
                return JSON.parse(cachedUser);
            }

            const user = await db.prisma.user.findUnique({
                where: { id: userId },
                select: {
                    id: true,
                    email: true,
                    password: true,
                    firstName: true,
                    lastName: true,
                    phone: true,
                    avatar: true,
                    role: true,
                    isEmailVerified: true,
                    isTwoFactorEnabled: true,
                    twoFactorSecret: true,
                    verificationToken: true,
                    resetToken: true,
                    resetTokenExpiry: true,
                    lastLogin: true,
                    createdAt: true,
                    updatedAt: true,
                    favorites: true,
                }
            });

            if (user) {
                await redisService.set(
                    `user:${userId}`,
                    JSON.stringify(user),
                    this.CACHE_TTL
                );
            }

            return user;
        } catch (error) {
            logger.error('Error getting user by ID:', error);
            throw error;
        }
    }

    public async updateUser(userId: string, updateData: IUserUpdate): Promise<User> {
        try {
            if (updateData.password) {
                updateData.password = await bcrypt.hash(updateData.password, 12);
            }

            const updatedUser = await db.prisma.user.update({
                where: { id: userId },
                data: updateData,
                select: {
                    id: true,
                    email: true,
                    password: true,
                    firstName: true,
                    lastName: true,
                    phone: true,
                    avatar: true,
                    role: true,
                    isEmailVerified: true,
                    isTwoFactorEnabled: true,
                    twoFactorSecret: true,
                    verificationToken: true,
                    resetToken: true,
                    resetTokenExpiry: true,
                    lastLogin: true,
                    createdAt: true,
                    updatedAt: true,
                    favorites: true,
                },
            });

            await redisService.del(`user:${userId}`);
            await redisService.set(
                `user:${userId}`,
                JSON.stringify(updatedUser),
                this.CACHE_TTL
            );

            return updatedUser;
        } catch (error) {
            logger.error('Error updating user:', error);
            throw error;
        }
    }

    public async deleteUser(userId: string): Promise<void> {
        try {
            const user = await this.getUserById(userId);
            if (!user) {
                throw new AuthenticationError('User not found');
            }

            if (user.avatar) {
                await deleteFile(user.avatar);
            }

            await db.prisma.$transaction([
                db.prisma.refreshToken.deleteMany({
                    where: { userId },
                }),
                db.prisma.reservation.deleteMany({
                    where: { userId },
                }),
                db.prisma.event.deleteMany({
                    where: { organizerId: userId },
                }),
                db.prisma.user.delete({
                    where: { id: userId },
                }),
            ]);

            await redisService.del(`user:${userId}`);
        } catch (error) {
            logger.error('Error deleting user:', error);
            throw error;
        }
    }

    public async getUserProfile(userId: string): Promise<IUserProfile> {
        try {
            const user = await db.prisma.user.findUnique({
                where: { id: userId },
                select: {
                    id: true,
                    firstName: true,
                    lastName: true,
                    avatar: true,
                    createdAt: true,
                    events: {
                        where: { status: 'PUBLISHED' },
                        select: {
                            id: true,
                            title: true,
                            images: true,
                            startDate: true,
                            category: true,
                        },
                    },
                },
            });

            if (!user) {
                throw new AuthenticationError('User not found');
            }

            // Transform the events to match IUserProfile format
            return {
                ...user,
                events: user.events.map(event => ({
                    ...event,
                    imageSrc: event.images[0] || '',  // Use first image as imageSrc
                    category: event.category.toString()
                }))
            };
        } catch (error) {
            logger.error('Error getting user profile:', error);
            throw error;
        }
    }


    public async getFavoriteEvents(userId: string): Promise<IPaginatedResponse> {
        try {
            const user = await this.getUserById(userId);
            if (!user) {
                throw new AuthenticationError('User not found');
            }

            const favoriteEvents = await db.prisma.event.findMany({
                where: {
                    favoritedBy: {
                        some: {
                            id: userId,
                        },
                    },
                    status: 'PUBLISHED',
                },
                select: {
                    id: true,
                    title: true,
                    images: true,
                    startDate: true,
                    endDate: true,
                    price: true,
                    category: true,
                    city: true,
                    country: true,
                },
            });

            return {
                data: favoriteEvents,
                pagination: {
                    total: favoriteEvents.length,
                    page: 1,
                    limit: favoriteEvents.length,
                    totalPages: 1
                }
            };
        } catch (error) {
            logger.error('Error getting favorite events:', error);
            throw error;
        }
    }

    public async toggleFavoriteEvent(userId: string, eventId: string): Promise<boolean> {
        try {
            const [user, event] = await Promise.all([
                this.getUserById(userId),
                db.prisma.event.findUnique({
                    where: { id: eventId },
                }),
            ]);

            if (!user || !event) {
                throw new AuthenticationError('User or event not found');
            }

            const isFavorited = await db.prisma.event.findFirst({
                where: {
                    id: eventId,
                    favoritedBy: {
                        some: {
                            id: userId,
                        },
                    },
                },
            });

            if (isFavorited) {
                await db.prisma.event.update({
                    where: { id: eventId },
                    data: {
                        favoritedBy: {
                            disconnect: {
                                id: userId,
                            },
                        },
                    },
                });
                return false;
            } else {
                await db.prisma.event.update({
                    where: { id: eventId },
                    data: {
                        favoritedBy: {
                            connect: {
                                id: userId,
                            },
                        },
                    },
                });
                return true;
            }
        } catch (error) {
            logger.error('Error toggling favorite event:', error);
            throw error;
        }
    }

    public async getUserStats(userId: string) {
        try {
            const [eventsCreated, eventsAttending, totalFavorites] = await Promise.all([
                db.prisma.event.count({
                    where: { organizerId: userId },
                }),
                db.prisma.reservation.count({
                    where: { userId },
                }),
                db.prisma.event.count({
                    where: {
                        favoritedBy: {
                            some: {
                                id: userId,
                            },
                        },
                    },
                }),
            ]);

            return {
                eventsCreated,
                eventsAttending,
                totalFavorites,
            };
        } catch (error) {
            logger.error('Error getting user stats:', error);
            throw error;
        }
    }

    public async searchUsers(query: string, page: number = 1, limit: number = 10) {
        try {
            const skip = (page - 1) * limit;

            const [users, total] = await Promise.all([
                db.prisma.user.findMany({
                    where: {
                        OR: [
                            { email: { contains: query, mode: 'insensitive' } },
                            { firstName: { contains: query, mode: 'insensitive' } },
                            { lastName: { contains: query, mode: 'insensitive' } },
                        ],
                    },
                    select: {
                        id: true,
                        firstName: true,
                        lastName: true,
                        avatar: true,
                    },
                    skip,
                    take: limit,
                }),
                db.prisma.user.count({
                    where: {
                        OR: [
                            { email: { contains: query, mode: 'insensitive' } },
                            { firstName: { contains: query, mode: 'insensitive' } },
                            { lastName: { contains: query, mode: 'insensitive' } },
                        ],
                    },
                }),
            ]);

            return {
                data: users,
                pagination: {
                    total,
                    page,
                    limit,
                    totalPages: Math.ceil(total / limit),
                },
            };
        } catch (error) {
            logger.error('Error searching users:', error);
            throw error;
        }
    }


    public async updateAvatar(userId: string, file: Express.Multer.File): Promise<string> {
        try {
            const user = await this.getUserById(userId);
            if (!user) {
                throw new AuthenticationError('User not found');
            }

            // Delete old avatar if exists
            if (user.avatar) {
                await deleteFile(user.avatar);
            }

            // Upload new avatar
            const avatarUrl = await uploadFile(file, 'avatars');

            // Update user record with new avatar URL
            await this.updateUser(userId, { avatar: avatarUrl });

            logger.info(`Avatar updated for user: ${userId}`);
            return avatarUrl;
        } catch (error) {
            logger.error('Error updating avatar:', error);
            throw error;
        }
    }
}

export const userService = UserService.getInstance();