import nodemailer from 'nodemailer';
import { logger } from './logger';

class EmailService {
    private static instance: EmailService;
    private transporter: nodemailer.Transporter;

    private constructor() {
        this.transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: Number(process.env.SMTP_PORT),
            secure: process.env.SMTP_SECURE === 'true',
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS,
            },
        });
    }

    public static getInstance(): EmailService {
        if (!EmailService.instance) {
            EmailService.instance = new EmailService();
        }
        return EmailService.instance;
    }

    public async verifyConnection(): Promise<void> {
        try {
            await this.transporter.verify();
            logger.info('Email service connected successfully');
        } catch (error) {
            logger.error('Email service connection failed:', error);
            throw error;
        }
    }

    public async sendMail(options: nodemailer.SendMailOptions): Promise<void> {
        try {
            await this.transporter.sendMail(options);
            logger.info('Email sent successfully');
        } catch (error) {
            logger.error('Failed to send email:', error);
            throw error;
        }
    }
}

export const emailService = EmailService.getInstance();