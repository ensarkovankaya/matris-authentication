import * as bodyParser from "body-parser";
import * as compression from "compression";
import * as cors from "cors";
import * as express from "express";
import * as expressValidator from 'express-validator';
import * as helmet from "helmet";
import * as morgan from "morgan";

import AuthenticationRoute from './routes/authentication.route';

class Server {
    public app: express.Application;

    constructor() {
        this.app = express();
        this.config();
        this.routes();
    }

    // application config
    public config() {
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
    }

    // application routes
    public routes(): void {
        this.app.use('/', AuthenticationRoute);
    }
}

export default new Server().app;
