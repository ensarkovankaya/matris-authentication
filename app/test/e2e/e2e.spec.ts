import { expect } from 'chai';
import { createServer, Server as HttpServer } from 'http';
import { after, before, describe, it } from 'mocha';
import "reflect-metadata";
import { IAuthToken } from '../../src/models/token.model';
import { Server } from '../../src/server';
import { TokenGenerator } from '../data/token/generator';
import { Database } from '../data/valid/database';
import { IDBUserModel } from '../data/valid/db.model';
import { HttpClient } from './http.client';

const DATABASE = new Database();

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
                    const response = await client.password<{
                        data: IAuthToken
                    }>({email: user.email, password: user.email, atExpiresIn: '1h', rtExpiresIn: '2h'});
                    expect(response.status).to.be.eq(200);
                    expect(response.data).to.be.an('object');
                    expect(response.data).to.have.key('data');
                    expect(response.data.data).to.be.a('object');
                    expect(response.data.data).to.have.keys(['accessToken', 'refreshToken']);
                    expect(response.data.data.accessToken).to.be.a('object');
                    expect(response.data.data.refreshToken).to.be.a('object');
                    expect(response.data.data.accessToken.token).to.be.a('string');
                    expect(response.data.data.accessToken.tokenType).to.be.eq('Bearer');
                    expect(response.data.data.accessToken.expiresAt).to.be.a('number');
                    expect(response.data.data.refreshToken.token).to.be.a('string');
                    expect(response.data.data.refreshToken.tokenType).to.be.eq('Bearer');
                    expect(response.data.data.refreshToken.expiresAt).to.be.a('number');
                    expect(response.data.data.refreshToken.notBefore).to.be.a('number');
                }
            } catch (e) {
                console.error(e);
                console.log(e.data.errors);
                throw e;
            }
        }).timeout(4000);

        it('should return UserNotFound', async () => {
            const users = DATABASE.multiple(10, (d: IDBUserModel) => d.deleted === true)
                .concat([{email: 'mail@mail.com', password: '12345678'}] as any);
            for (const user of users) {
                try {
                    await client.password<{
                        data: null,
                        errors: Array<{msg: string, location: string, param: string}>
                    }>({email: user.email, password: user.email, atExpiresIn: '1h', rtExpiresIn: '2h'});
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
                    await client.password<{
                        data: null,
                        errors: Array<{msg: string, location: string, param: string}>
                    }>({email: user.email, password: user.email, atExpiresIn: '1h', rtExpiresIn: '2h'});
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
                    await client.password<{
                        data: null,
                        errors: Array<{msg: string, location: string, param: string}>
                    }>({email: user.email, password: '12345678', atExpiresIn: '1h', rtExpiresIn: '2h'});
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

    describe('Refresh', () => {
        it('should return new tokens', async () => {
            const generator = new TokenGenerator();

            const tokens = await generator.authToken(
                process.env.JWT_SECRET, 0, '1m',
                generator.db.one(u => u.active && !u.deleted)
            );

            const response = await client.refresh<{data: IAuthToken}>({
                accessToken: tokens.accessToken,
                refreshToken: tokens.refreshToken,
                atExpiresIn: '1h',
                rtExpiresIn: '2h'
            });

            expect(response.status).to.be.eq(200);
            expect(response.data).to.be.an('object');
            expect(response.data.data).to.be.an('object');
            expect(response.data.data).to.have.keys(['accessToken', 'refreshToken']);

            expect(response.data.data.accessToken).to.be.an('object');
            expect(response.data.data.accessToken).to.have.keys(['tokenType', 'token', 'expiresAt']);

            expect(response.data.data.accessToken.token).to.be.a('string');
            expect(response.data.data.accessToken.token.length).to.be.gt(100);

            expect(response.data.data.accessToken.tokenType).to.be.a('string');
            expect(response.data.data.accessToken.tokenType).to.be.eq('Bearer');

            expect(response.data.data.accessToken.expiresAt).to.be.a('number');
            expect(new Date(response.data.data.accessToken.expiresAt * 1000)).to.be.a('date');

            expect(response.data.data.refreshToken).to.be.an('object');
            expect(response.data.data.refreshToken).to.have.keys(['tokenType', 'token', 'expiresAt', 'notBefore']);

            expect(response.data.data.refreshToken.token).to.be.a('string');
            expect(response.data.data.refreshToken.token.length).to.be.gt(100);

            expect(response.data.data.refreshToken.tokenType).to.be.a('string');
            expect(response.data.data.refreshToken.tokenType).to.be.eq('Bearer');

            expect(response.data.data.refreshToken.expiresAt).to.be.a('number');
            expect(new Date(response.data.data.refreshToken.expiresAt * 1000)).to.be.a('date');

            expect(response.data.data.refreshToken.notBefore).to.be.a('number');
            expect(new Date(response.data.data.refreshToken.notBefore * 1000)).to.be.a('date');
        });
    });
});

after('Stop Server', () => server.close(() => {
    console.info('Test Server closed.');
    process.exit();
}));
