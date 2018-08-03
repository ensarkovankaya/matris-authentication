import { expect } from 'chai';
import { createServer, Server as HttpServer } from 'http';
import { after, before, describe, it } from 'mocha';
import "reflect-metadata";
import { Server } from '../../src/server';
import { DataSource } from '../data/data';
import { IDBUserModel } from '../data/valid/db.model';
import { HttpClient } from './http.client';

const PATH = __dirname + '/../data/valid/db.json';
const DATA = new DataSource<IDBUserModel>().load(PATH);

let server: HttpServer;

const PORT = parseInt(process.env.PORT || '1234', 10);
const HOST = process.env.HOST || '0.0.0.0';
const VERSION = process.env.VERSION || '/v1';
const BASEURL = `http://${HOST}:${PORT}${VERSION}`;

const client = new HttpClient(BASEURL);

class ShouldNotSucceed extends Error {
    public name = 'ShouldNotSucceed';
}

before('Load Data', async () => {
    const express = new Server();
    server = createServer(express.app);
    return await server.listen(PORT, HOST, () => {
        console.info(`Authentication Test Server start on host ${HOST} port ${PORT}.`);
    });
});

describe('E2E', () => {
    describe('Password', () => {
        it('should return token', async () => {
            const users = DATA.multiple(10, (d: IDBUserModel) => d.active === true && d.deleted === false);
            for (const user of users) {
                const response = await client.password<{data: string}>({email: user.email, password: user.email});
                expect(response.status).to.be.eq(200);
                expect(response.data).to.be.an('object');
                expect(response.data).to.have.key('data');
                expect(response.data.data).to.be.a('string');
                expect(response.data.data.length).to.be.gte(200);
            }
        }).timeout(4000);

        it('should return UserNotFound', async () => {
            const users = DATA.multiple(10, (d: IDBUserModel) => d.deleted === true)
                .concat([{email: 'mail@mail.com', password: '12345678'}] as any);
            for (const user of users) {
                try {
                    await client.password<{data: string}>({email: user.email, password: user.email});
                    throw new ShouldNotSucceed();
                } catch (e) {
                    expect(e.name).to.be.eq('HttpClientError');
                    expect(e.status).to.be.eq(400);
                    expect(e.data).to.be.an('object');
                    expect(e.data).to.have.keys(['errors', 'data']);
                    expect(e.data.data).to.be.eq(null);
                    expect(e.data.errors).to.be.an('array');
                    expect(e.data.errors).to.be.deep.eq([ { msg: 'UserNotFound', location: 'body', param: 'email' } ]);
                }
            }
        }).timeout(4000);

        it('should return UserNotActive', async () => {
            const users = DATA.multiple(10, (d: IDBUserModel) => d.active === false && d.deleted === false);
            for (const user of users) {
                try {
                    await client.password<{data: string}>({email: user.email, password: user.email});
                    throw new ShouldNotSucceed();
                } catch (e) {
                    expect(e.name).to.be.eq('HttpClientError');
                    expect(e.status).to.be.eq(400);
                    expect(e.data).to.be.an('object');
                    expect(e.data).to.have.keys(['errors', 'data']);
                    expect(e.data.data).to.be.eq(null);
                    expect(e.data.errors).to.be.an('array');
                    expect(e.data.errors).to.be.deep.eq([ { msg: 'UserNotActive', location: 'body', param: 'email' } ]);
                }
            }
        }).timeout(4000);

        it('should return InvalidPasswordResponse', async () => {
            const users = DATA.multiple(10, (d: IDBUserModel) => d.active === true && d.deleted === false);
            for (const user of users) {
                try {
                    await client.password<{data: string}>({email: user.email, password: '12345678'});
                    throw new ShouldNotSucceed();
                } catch (e) {
                    expect(e.name).to.be.eq('HttpClientError');
                    expect(e.status).to.be.eq(400);
                    expect(e.data).to.be.an('object');
                    expect(e.data).to.have.keys(['errors', 'data']);
                    expect(e.data.data).to.be.eq(null);
                    expect(e.data.errors).to.be.an('array');
                    expect(e.data.errors).to.be.deep.eq(
                        [{ msg: 'InvalidPassword', location: 'body', param: 'password' }]
                    );
                }
            }
        }).timeout(4000);
    });
});

after('Stop Server', () => server.close(() => {
    console.info('Test Server closed.');
    process.exit();
}));
