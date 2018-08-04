import { readFileSync } from 'fs';
import { DataSource } from '../data';

export interface IDataModel {
    id: string;
    role: string;
    email: string;
    token: string;
    secret: string;
    iat: number;
    exp: number;
}

export interface ITokenModel extends IDataModel {
    type: string;
}

const VALID_PATH = __dirname + '/valid.json';
const VALID_DATA: IDataModel[] = JSON.parse(readFileSync(VALID_PATH, {encoding: 'utf8'}));

const INVALID_PATH = __dirname + '/invalid.json';
const INVALID_DATA: IDataModel[] = JSON.parse(readFileSync(INVALID_PATH, {encoding: 'utf8'}));

const EXPIRED_PATH = __dirname + '/expired.json';
const EXPIRED_DATA: IDataModel[] = JSON.parse(readFileSync(EXPIRED_PATH, {encoding: 'utf8'}));

export class TokenDataSource extends DataSource<ITokenModel> {
    constructor() {
        super();
        this.append(VALID_DATA.map(d => ({...d, type: 'valid'})));
        this.append(INVALID_DATA.map(d => ({...d, type: 'invalid'})));
        this.append(EXPIRED_DATA.map(d => ({...d, type: 'expired'})));
    }
}
