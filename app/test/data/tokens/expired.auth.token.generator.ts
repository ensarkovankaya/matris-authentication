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
        const jwtid = genereateID(24);

        const accessToken: string = await new Promise<string>((resolve, reject) => {
            sign({}, secret, {
                jwtid,
                subject: user._id,
                audience: user.role,
                expiresIn: '1d'
            },
                (err, tkn) => err ? reject(err) : resolve(tkn)
            );
        });

        const accessDecoded = await new Promise<IDecodedTokenModel<IAccessTokenPayload>>((resolve, reject) => {
            try {
                resolve(decode(accessToken, {json: true, complete: true}) as any);
            } catch (e) {
                reject(e);
            }
        });

        const refreshToken: string = await new Promise<string>((resolve, reject) => {
            sign({}, secret, {
                subject: jwtid,
                notBefore: '1d',
                expiresIn: '2d'
            },
                (err, tkn) => err ? reject(err) : resolve(tkn)
            );
        });

        const refreshDecoded = await new Promise<IDecodedTokenModel<IAccessTokenPayload>>((resolve, reject) => {
            try {
                resolve(decode(refreshToken, {json: true, complete: true}) as any);
            } catch (e) {
                reject(e);
            }
        });

        data.push({accessToken, accessDecoded, refreshToken, refreshDecoded, secret});
    }

    writeFileSync(__dirname + '/auth-expired.json', JSON.stringify(data), {encoding: 'utf8'});
};

generate();
