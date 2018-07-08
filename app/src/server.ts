import * as bodyParser from "body-parser";
import * as compression from "compression";
import * as cors from "cors";
import * as express from "express";
import * as expressValidator from 'express-validator';
import * as helmet from "helmet";
import * as morgan from "morgan";
import "reflect-metadata";
import { Container } from 'typedi';
import { Logger } from './logger';

import { AuthenticationRoute } from './routes/authentication.route';

class Server {
    public app: express.Application;
    private logger: Logger;

    constructor() {
        this.logger = new Logger('Server');
        this.app = express();
        this.config();
        this.routes();
    }

    // application config
    public config() {
        try {
            this.app.use(bodyParser.json());
            this.app.use(morgan("dev"));
            this.app.use(compression());
            this.app.use(helmet());
            this.app.use(cors());
            this.app.use(expressValidator());

            // cors
            this.app.use((req, res, next) => {
                res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
                res.header(
                    "Access-Control-Allow-Headers",
                    "Origin, X-Requested-With, Content-Type, Accept, Authorization, Access-Control-Allow-Credentials",
                );
                res.header("Access-Control-Allow-Credentials", "true");
                next();
            });

            // Http Log
            this.app.use((req, res, next) => {
                this.logger.http('Incoming Request', {
                    params: req.params,
                    query: req.query,
                    headers: req.headers,
                    body: req.body,
                    baseUrl: req.baseUrl,
                    originalUrl: req.originalUrl,
                    httpVersion: req.httpVersion,
                    url: req.url,
                    method: req.method
                });
                next();
            });
        } catch (err) {
            this.logger.error('Configuration failed', err);
            throw err;
        }
    }

    // application routes
    public routes(): void {
        try {
            this.app.use('/', Container.get<AuthenticationRoute>(AuthenticationRoute).router);
        } catch (err) {
            this.logger.error('Route configuration failed', err);
            throw err;
        }
    }
}

export default new Server().app;
