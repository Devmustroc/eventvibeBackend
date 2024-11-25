import express from 'express';
import {authController} from "@/controllers/auth.controller";
import {authMiddleware} from "@/middlewares/auth.middleware";
import {securityMiddleware} from "@/middlewares/security.middleware";


const router = express.Router();

// Apply rate limiting to auth routes
router.use(securityMiddleware.authRateLimit);

// Public routes
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh-token', authController.refreshToken);
router.get('/verify-email', authController.verifyEmail);

// Protected routes
router.use(authMiddleware.verifyToken);

router.post('/logout', authController.logout);
router.post('/enable-2fa', authController.enable2FA);
router.post('/verify-2fa', authController.verify2FA);

export default router;