import { expect } from 'chai';
import { createServer, Server as HttpServer } from 'http';
import { after, before, describe, it } from 'mocha';
import "reflect-metadata";
import { Server } from '../../src/server';
import { TokenDataSource } from '../data/tokens/token';
import { Database } from '../data/valid/database';
import { IDBUserModel } from '../data/valid/db.model';
import { HttpClient } from './http.client';

const DATABASE = new Database();
const TOKENS = new TokenDataSource();

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
            try {
                const users = DATABASE.multiple(10, (d: IDBUserModel) => d.active === true && d.deleted === false);
                for (const user of users) {
                    const response = await client.password<{data: string}>({email: user.email, password: user.email});
                    expect(response.status).to.be.eq(200);
                    expect(response.data).to.be.an('object');
                    expect(response.data).to.have.key('data');
                    expect(response.data.data).to.be.a('string');
                    expect(response.data.data.length).to.be.gte(150);
                }
            } catch (e) {
                console.error(e);
                throw e;
            }
        }).timeout(4000);

        it('should return UserNotFound', async () => {
            const users = DATABASE.multiple(10, (d: IDBUserModel) => d.deleted === true)
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
            const users = DATABASE.multiple(10, (d: IDBUserModel) => d.active === false && d.deleted === false);
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
            const users = DATABASE.multiple(10, (d: IDBUserModel) => d.active === true && d.deleted === false);
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

    describe('Verify', () => {

        it('should return decoded tokens', async () => {
            // Get valid tokens from source
            const tokens = TOKENS.multiple(20, t => t.type === 'valid');
            const secret = process.env.JWT_SECRET;

            for (const data of tokens) {
                if (secret !== data.secret) {
                    throw new Error(`Secrets not matched. Expected: "${data.secret}" Actual: "${secret}"`);
                }
                const response = await client.verify<{data: {
                    id: string;
                    email: string;
                    role: string;
                    iat: number;
                    exp: number
                }}>({token: data.token});
                expect(response.status).to.be.eq(200);
                expect(response.data).to.be.an('object');
                expect(response.data).to.have.key('data');
                expect(response.data.data).to.be.an('object');
                expect(response.data.data).to.have.keys(['id', 'email', 'role', 'iat', 'exp']);

                expect(response.data.data.id).to.be.a('string');
                expect(response.data.data.id).to.be.eq(data.id);

                expect(response.data.data.email).to.be.a('string');
                expect(response.data.data.email).to.be.eq(data.email);

                expect(response.data.data.role).to.be.a('string');
                expect(response.data.data.role).to.be.eq(data.role);

                expect(response.data.data.iat).to.be.a('number');
                expect(response.data.data.iat).to.be.eq(data.iat);

                expect(response.data.data.exp).to.be.a('number');
                expect(response.data.data.exp).to.be.eq(data.exp);
            }
        });

        it('should response with token expired', async () => {
            // Get valid tokens from source
            const tokens = TOKENS.multiple(20, t => t.type === 'expired');
            const secret = process.env.JWT_SECRET;

            for (const data of tokens) {
                try {
                    if (secret !== data.secret) {
                        throw new Error(`Secrets not matched. Expected: "${data.secret}" Actual: "${secret}"`);
                    }
                    await client.verify({token: data.token});
                } catch (e) {
                    expect(e.name).to.be.eq('HttpClientError');
                    expect(e.status).to.be.eq(400);
                    expect(e.data).to.be.an('object');
                    expect(e.data).to.have.keys(['errors', 'data']);
                    expect(e.data.data).to.be.eq(null);
                    expect(e.data.errors).to.be.an('array');
                    expect(e.data.errors).to.be.deep.eq([{ msg: 'TokenExpired', location: 'body', param: 'token' }]);
                }
            }
        });

        it('should response with invalid token', async () => {
            // Get valid tokens from source
            const tokens = TOKENS.multiple(20, t => t.type === 'invalid');

            for (const data of tokens) {
                try {
                    await client.verify({token: data.token});
                } catch (e) {
                    expect(e.name).to.be.eq('HttpClientError');
                    expect(e.status).to.be.eq(400);
                    expect(e.data).to.be.an('object');
                    expect(e.data).to.have.keys(['errors', 'data']);
                    expect(e.data.data).to.be.eq(null);
                    expect(e.data.errors).to.be.an('array');
                    expect(e.data.errors).to.be.deep.eq([{ msg: 'InvalidToken', location: 'body', param: 'token' }]);
                }
            }
        });
    });
});

after('Stop Server', () => server.close(() => {
    console.info('Test Server closed.');
    process.exit();
}));
