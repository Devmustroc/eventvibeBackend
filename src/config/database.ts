import { PrismaClient } from '@prisma/client';
import {logger} from "@/config/logger";

class Database {
    private static instance: Database;
    public prisma: PrismaClient;

    private constructor() {
        this.prisma = new PrismaClient({
            log: [
                { emit: 'event', level: 'query' },
                { emit: 'event', level: 'error' },
                { emit: 'event', level: 'info' },
                { emit: 'event', level: 'warn' },
            ]
        });

        // Logging
        this.prisma.$on('query', (e: any) => {
            logger.debug('Query: ' + e.query);
            logger.debug('Duration: ' + e.duration + 'ms');
        });

        this.prisma.$on('error', (e: any) => {
            logger.error('Prisma Error: ', e.message);
        });
    }

    public static getInstance(): Database {
        if (!Database.instance) {
            Database.instance = new Database();
        }
        return Database.instance;
    }

    public async connect(): Promise<void> {
        try {
            await this.prisma.$connect();
            logger.info('Database Connected');
        } catch (error) {
            logger.error('Error while connecting to database', error);
            process.exit(1);
        }
    };

    public async disconnect(): Promise<void> {
        try {
            await this.prisma.$disconnect();
            logger.info('Database Disconnected');
        } catch (error) {
            logger.error('Error while disconnecting from database', error);
            process.exit(1);
        }
    };

    public async verifyConnection(): Promise<void> {
        try {
            await this.prisma.$queryRaw('SELECT 1');
            logger.info('Database Connection Verified');
        } catch (error) {
            logger.error('Error while verifying database connection', error);
            process.exit(1);
        }
    };

    public async reset(): Promise<void> {
        try {
            await this.prisma.$executeRaw('TRUNCATE TABLE "User" CASCADE');
            logger.info('Database Reset');
        } catch (error) {
            logger.error('Error while resetting database', error);
            process.exit(1);
        }
    };
}

export const db = Database.getInstance();