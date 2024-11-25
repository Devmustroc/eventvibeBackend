import { S3Client, PutObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { logger } from '../config/logger';
import crypto from 'crypto';

const s3Client = new S3Client({
    region: process.env.AWS_REGION!,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
    },
});

export const uploadFile = async (
    file: Express.Multer.File,
    path: string
): Promise<string> => {
    try {
        const fileExtension = file.originalname.split('.').pop();
        const randomName = crypto.randomBytes(16).toString('hex');
        const key = `${path}/${randomName}.${fileExtension}`;

        await s3Client.send(
            new PutObjectCommand({
                Bucket: process.env.AWS_BUCKET_NAME!,
                Key: key,
                Body: file.buffer,
                ContentType: file.mimetype,
            })
        );

        return `https://${process.env.AWS_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;
    } catch (error) {
        logger.error('Error uploading file:', error);
        throw new Error('Failed to upload file');
    }
};

export const deleteFile = async (fileUrl: string): Promise<void> => {
    try {
        const key = fileUrl.split('.amazonaws.com/')[1];

        await s3Client.send(
            new DeleteObjectCommand({
                Bucket: process.env.AWS_BUCKET_NAME!,
                Key: key,
            })
        );
    } catch (error) {
        logger.error('Error deleting file:', error);
        throw new Error('Failed to delete file');
    }
};