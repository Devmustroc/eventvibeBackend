import express from 'express';
import { userController } from '../controllers/user.controller';
import { authMiddleware } from '../middlewares/auth.middleware';
import multer from 'multer';

const router = express.Router();

// Configure multer for avatar uploads
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Not an image file'));
        }
    },
});

// All routes require authentication
router.use(authMiddleware.verifyToken);

// Profile routes
router.get('/me', userController.getCurrentUser);
router.put('/me', userController.updateProfile);
router.delete('/me', userController.deleteAccount);
router.post('/me/avatar', upload.single('avatar'), userController.updateAvatar);

// Favorite events routes
router.get('/me/favorites', userController.getFavoriteEvents);
router.post('/favorites/:eventId', userController.toggleFavoriteEvent);
router.delete('/favorites/:eventId', userController.toggleFavoriteEvent);

// Public profile routes
router.get('/:userId/profile', userController.getUserProfile);

export default router;