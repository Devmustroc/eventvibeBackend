import { Request, Response, NextFunction } from 'express';

import {userUpdateSchema, validate} from "@/utils/validation.util";
import { UserService } from '@/services/user.service';


export class UserController {
    private static instance: UserController;
    private userService: UserService;

    private constructor() {
        this.userService = UserService.getInstance();
    }

    public static getInstance(): UserController {
        if (!UserController.instance) {
            UserController.instance = new UserController();
        }
        return UserController.instance;
    }

    public getCurrentUser = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const user = await this.userService.getUserById(req.user!.userId);

            res.json({
                status: 'success',
                data: { user },
            });
        } catch (error) {
            next(error);
        }
    };

    public updateProfile = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const updateData = validate(userUpdateSchema, req.body);
            const updatedUser = await this.userService.updateUser(req.user!.userId, updateData);

            res.json({
                status: 'success',
                data: { user: updatedUser },
            });
        } catch (error) {
            next(error);
        }
    };

    public updateAvatar = async (req: Request, res: Response, next: NextFunction) => {
        try {
            if (!req.file) {
                throw new Error('No file uploaded');
            }

            const avatarUrl = await this.userService.updateAvatar(
                req.user!.userId,
                req.file
            );

            res.json({
                status: 'success',
                data: { avatarUrl },
            });
        } catch (error) {
            next(error);
        }
    };

    public deleteAccount = async (req: Request, res: Response, next: NextFunction) => {
        try {
            await this.userService.deleteUser(req.user!.userId);

            res.clearCookie('refreshToken');
            res.json({
                status: 'success',
                message: 'Account deleted successfully',
            });
        } catch (error) {
            next(error);
        }
    };

    public getUserProfile = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { userId } = req.params;
            const profile = await this.userService.getUserProfile(userId);

            res.json({
                status: 'success',
                data: { profile },
            });
        } catch (error) {
            next(error);
        }
    };

    public getFavoriteEvents = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const events = await this.userService.getFavoriteEvents(req.user!.userId);

            res.json({
                status: 'success',
                data: { events },
            });
        } catch (error) {
            next(error);
        }
    };

    public toggleFavoriteEvent = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { eventId } = req.params;
            const result = await this.userService.toggleFavoriteEvent(req.user!.userId, eventId);

            res.json({
                status: 'success',
                data: { isFavorited: result },
            });
        } catch (error) {
            next(error);
        }
    };
}

export const userController = UserController.getInstance();