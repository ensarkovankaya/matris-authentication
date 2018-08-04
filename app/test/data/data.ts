import { readFileSync } from 'fs';

/**
 * Base Datasource class
 */
export class DataSource<T> {

    public data: T[];

    constructor() {
        this.data = [];
    }

    /**
     * Loads source from file and appends current data
     * @param {string} path: File path
     * @param {boolean} reset: Reset data source before loading new source
     */
    public load(path: string, reset: boolean = false): this {
        const data = JSON.parse(readFileSync(path, {encoding: 'utf8'}));
        if (reset) {
            this.reset();
        }
        this.append(data);
        return this;
    }

    /**
     * Appends given data to data source
     * @param {T[]} data: Data
     */
    public append(data: T[]): this {
        this.data = this.data.concat(data);
        return this;
    }

    /**
     * Reset current data source
     */
    public reset(): this {
        this.data = [];
        return this;
    }

    /**
     * Return one data
     */
    public one(filter?: (data: T) => boolean) {
        if (filter) {
            return this.choose(this.filter(filter));
        }
        return this.choose(this.data);
    }

    /**
     * Returns given number of data if exists
     * @param limit: Maximum number of data
     */
    public multiple(limit: number, filter?: (data: T) => boolean) {
        if (filter) {
            return this.shuffle(this.filter(filter).slice()).slice(0, limit);
        }
        return this.shuffle(this.data.slice()).slice(0, limit);
    }

    /**
     * Filters data with given function
     * @param filter: Filter function
     */
    public filter(filter: (data: T) => boolean): T[] {
        return this.data.filter(filter);
    }

    /**
     * Generates partial data. Returns new object which have only given fields.
     * @param {object} obj
     * @param {string[]} fields
     * @return {Partial<T>}
     */
    public partial(obj: object, fields: string[]): Partial<T> {
        const newObj = {};
        fields.forEach(field => newObj[field] = obj[field]);
        return newObj;
    }

    /**
     * Shuffles array in place.
     * @param {Array} array: Array containing the items.
     */
    public shuffle(array: T[]): T[] {
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [array[i], array[j]] = [array[j], array[i]];
        }
        return array;
    }

    /**
     * Makes random choice from array
     * @param {any[]} choices
     * @return {any}
     */
    public choose(choices: T[]): T {
        if (choices.length === 0) {
            throw new Error('Array is empty');
        }
        const index = Math.floor(Math.random() * choices.length);
        return choices[index];
    }
}
