import { readFileSync } from 'fs';
import { DataSource } from '../data';
import { IAuthToken, IToken } from './models';

const VALID_PATH = __dirname + '/valid.json';
const VALID_DATA: IToken[] = JSON.parse(readFileSync(VALID_PATH, {encoding: 'utf8'}));

const AUTH_EXPIRED_PATH = __dirname + '/auth-expired.json';
const AUTH_EXPIRED_DATA: IAuthToken[] = JSON.parse(readFileSync(AUTH_EXPIRED_PATH, {encoding: 'utf8'}));

const AUTH_VALID_PATH = __dirname + '/auth-valid.json';
const AUTH_VALID_DATA: IAuthToken[] = JSON.parse(readFileSync(AUTH_VALID_PATH, {encoding: 'utf8'}));

const EXPIRED_PATH = __dirname + '/expired.json';
const EXPIRED_DATA: IToken[] = JSON.parse(readFileSync(EXPIRED_PATH, {encoding: 'utf8'}));

export class ValidTokenDataSource extends DataSource<IToken> {
    constructor() {
        super();
        this.append(VALID_DATA);
    }
}

export class ExpiredTokenDataSource extends DataSource<IToken> {
    constructor() {
        super();
        this.append(EXPIRED_DATA);
    }
}

export class ValidAuthTokenDataSource extends DataSource<IAuthToken> {
    constructor() {
        super();
        this.append(AUTH_VALID_DATA);
    }
}

export class ExpiredAuthTokenDataSource extends DataSource<IAuthToken> {
    constructor() {
        super();
        this.append(AUTH_EXPIRED_DATA);
    }
}
