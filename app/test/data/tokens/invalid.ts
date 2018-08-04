import { writeFileSync } from 'fs';
import { JWTService } from '../../../src/services/jwt.service';
import { DataSource } from "../data";
import { IDBUserModel } from "../valid/db.model";

const PATH = __dirname + '/../valid/db.json';
const database = new DataSource<IDBUserModel>().load(PATH);

const secret = 'randomsecret';

/**
 * Generates invalid token from test data and writes to invalid.json file
 */
const generate = async () => {
    const users = database.filter((d => d.deleted === false && d.active === true));
    const service = new JWTService({expiresIn: '5y', secret});
    const data = [];
    for (const user of users) {
        const token = await service.sign({id: user._id, email: user.email, role: user.role});
        const decoded = await service.verify<{iat: number, exp: number}>(token);
        const payload = {
            id: user._id,
            role: user.role,
            email: user.email,
            token,
            secret,
            iat: decoded.iat,
            exp: decoded.exp
        };
        data.push(payload);
    }

    writeFileSync(__dirname + '/invalid.json', JSON.stringify(data), {encoding: 'utf8'});
};

generate();
