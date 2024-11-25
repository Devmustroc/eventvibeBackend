import Redis from 'ioredis';
import { logger } from './logger';

class RedisService {
    private static instance: RedisService;
    public client: Redis;

    private constructor() {
        this.client = new Redis(process.env.REDIS_URL!, {
            maxRetriesPerRequest: 3,
            enableOfflineQueue: false,
            retryStrategy(times) {
                const delay = Math.min(times * 50, 2000);
                return delay;
            },
        });

        this.setupEventListeners();
    }

    private setupEventListeners() {
        this.client.on('connect', () => {
            logger.info('Redis connected successfully');
        });

        this.client.on('error', (error) => {
            logger.error('Redis connection error:', error);
        });

        this.client.on('close', () => {
            logger.warn('Redis connection closed');
        });
    }

    public static getInstance(): RedisService {
        if (!RedisService.instance) {
            RedisService.instance = new RedisService();
        }
        return RedisService.instance;
    }

    public async set(key: string, value: string, expireTime?: number): Promise<void> {
        try {
            if (expireTime) {
                await this.client.set(key, value, 'EX', expireTime);
            } else {
                await this.client.set(key, value);
            }
        } catch (error) {
            logger.error('Redis set error:', error);
            throw error;
        }
    }

    public async get(key: string): Promise<string | null> {
        try {
            return await this.client.get(key);
        } catch (error) {
            logger.error('Redis get error:', error);
            throw error;
        }
    }

    public async del(key: string): Promise<void> {
        try {
            await this.client.del(key);
        } catch (error) {
            logger.error('Redis delete error:', error);
            throw error;
        }
    }
}

export const redisService = RedisService.getInstance();