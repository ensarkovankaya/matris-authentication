import { DataSource } from "../data";
import { IDBUserModel } from './db.model';

const PATH = __dirname + '/db.json';

export class Database extends DataSource<IDBUserModel> {
    constructor() {
        super();
        this.load(PATH);
    }
}
