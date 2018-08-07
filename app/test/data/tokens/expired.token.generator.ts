import { writeFileSync } from 'fs';
import { decode, sign } from 'jsonwebtoken';
import { IAccessTokenPayload, IDecodedTokenModel } from '../../../src/models/token.model';
import { DataSource } from "../data";
import { IDBUserModel } from "../valid/db.model";

const PATH = __dirname + '/../valid/db.json';
const database = new DataSource<IDBUserModel>().load(PATH);

const genereateID = (length: number): string => {
    let id: string = '';
    while (id.length < length) {
        id += Math.random().toString(36).substr(2, 9);
    }
    return id.slice(0, length);
};

/**
 * Generates token from test data and writes to valid.json file
 */
const generate = async () => {
    const data = [];

    const users = database.filter((d => d.deleted === false && d.active === true));
    for (const user of users) {

        const secret = genereateID(10);

        const token: string = await new Promise<string>((resolve, reject) => {
            sign({}, secret, {
                jwtid: genereateID(24),
                subject: user._id,
                audience: user.role,
                expiresIn: '1m'
            },
                (err, tkn) => err ? reject(err) : resolve(tkn)
            );
        });
        const decoded = await new Promise<IDecodedTokenModel<IAccessTokenPayload>>((resolve, reject) => {
            try {
                resolve(decode(token, {json: true, complete: true}) as any);
            } catch (e) {
                reject(e);
            }
        });

        data.push({ token, decoded, secret });
    }

    writeFileSync(__dirname + '/expired.json', JSON.stringify(data), {encoding: 'utf8'});
};

generate();
