import 'dotenv/config';
import express, { Application } from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import compression from "compression";
import morgan from "morgan";
import {db} from "@/config/database";
import {logger} from "@/config/logger";
import {emailService} from "@/config/email";


class App {
    public app : Application;
    public port : number;

    constructor() {
        this.app = express();
        this.port = Number(process.env.PORT) || 3000;

        this.initializeMiddlewares();
        this.initializeServices();
    }

    private initializeMiddlewares(): void {
        this.app.use(helmet());
        this.app.use(cors({
            origin: process.env.CORS_ORIGIN,
            credentials: true,
        }));

        // Body parsing Middlewares
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(cookieParser());

        // compression
        this.app.use(compression());

        // Logging
        if (process.env.NODE_ENV === "development") {
            this.app.use(morgan("dev"));
        }

        this.app.get("/health", (req, res) => {
            res.status(200).send("Health Check");
        });
    }

    private async initializeServices(): Promise<void> {
        try {
            // Connect to database
            await db.connect();

            // Verify email service
            await emailService.verifyConnection();

            // Redis is already connected via Singleton
            logger.info("Services Initialized Successfully");
        } catch (error) {
            logger.error("Error while initializing services", error);
            process.exit(1);
        }
    }

    public listen(): void {
        this.app.listen(this.port, () => {
            logger.info(`Server is running on port ${this.port}`);
            logger.info(`Environment: ${process.env.NODE_ENV}`);
        });
    };
}

process.on("unhandledRejection", (reason, promise) => {
    logger.error("Unhandled Rejection at:", promise, "reason:", reason);
    process.exit(1);
});

process.on("uncaughtException", (error) => {
    logger.error("Uncaught Exception thrown", error);
    process.exit(1);
});

const app = new App();
app.listen();

export default app;