import { expect } from 'chai';
import { describe, it } from 'mocha';
import "reflect-metadata";
import { Role } from '../../../src/models/role.model';
import { IAccessTokenPayload, IDecodedTokenModel } from '../../../src/models/token.model';
import { AuthenticationService } from '../../../src/services/auth.service';
import { TokenGenerator } from '../../data/token/generator';

class ShouldNotSucceed extends Error {
    public name = 'ShouldNotSucceed';
}

const generator = new TokenGenerator();

describe('Unit -> Services -> JWTService', () => {
    it('should initialize', () => {
        const service = new AuthenticationService();
        expect(service.configure).to.be.a('function');
        expect(service.sign).to.be.a('function');
        expect(service.verify).to.be.a('function');
        expect(service.secret).to.be.eq(undefined);
    });

    it('should configure', () => {
        const service = new AuthenticationService();
        service.configure({
            secret: 'abc'
        });
        expect(service.secret).to.be.eq('abc');
    });

    describe('Sign', () => {
        it('should return token', async () => {
            const service = new AuthenticationService();
            service.configure({
                secret: 'topsecret'
            });
            const token = await service.sign({}, {
                subject: 'userID',
                expiresIn: '1h',
                audience: 'ADMIN',
                jwtid: '1'
            });
            expect(token).to.be.a('string');
            expect(token.length).to.be.gte(100);
            expect(token.split('.').length).to.be.eq(3);
        });
    });

    describe('Verify', () => {
        it('should verify token', async () => {
            const users = generator.db.multiple(10, u => u.active && !u.deleted);

            for (const user of users) {
                const service = new AuthenticationService();
                service.configure({ secret: 'secret' });

                const jti = generator.generateID(24);
                const token = await generator.accessToken(jti, '1h', user._id, user.role, 'secret');
                const payload = await service.verify<IAccessTokenPayload>(token);

                expect(payload).to.be.an('object');
                expect(payload).to.have.keys(['sub', 'aud', 'jti', 'iat', 'exp']);

                expect(payload.sub).to.be.a('string');
                expect(payload.sub).to.be.eq(user._id);

                expect(payload.aud).to.be.a('string');
                expect(payload.aud).to.be.eq(user.role);

                expect(payload.jti).to.be.a('string');
                expect(payload.jti).to.be.eq(jti);

                expect(payload.exp).to.be.a('number');
                expect(payload.iat).to.be.a('number');
            }
        });

        it('should raise JsonWebTokenError', async () => {
            const users = generator.db.multiple(10, u => u.active && !u.deleted);

            for (const user of users) {
                try {
                    const service = new AuthenticationService();
                    service.configure({ secret: 'notvalidsecret'});

                    const token = await generator.accessToken('1', '1h', user._id, user.role, 'secret');

                    await service.verify(token);
                    throw new ShouldNotSucceed();
                } catch (e) {
                    expect(e.name).to.be.eq('JsonWebTokenError');
                }
            }
        });
    });

    describe('Decode', () => {
        it('should decode token', async () => {
            const users = generator.db.multiple(10, u => u.active && !u.deleted);

            for (const user of users) {
                const service = new AuthenticationService();
                service.configure({ secret: 'secret' });

                const token = await generator.accessToken('1', '1h', user._id, user.role, 'secret');

                const decoded = await service
                    .decode<IDecodedTokenModel<IAccessTokenPayload>>(token, {json: true, complete: true});

                expect(decoded).to.be.an('object');
                expect(decoded).to.have.keys(['header', 'payload', 'signature']);

                expect(decoded.payload).to.be.an('object');
                expect(decoded.payload).to.have.keys(['sub', 'aud', 'jti', 'iat', 'exp']);

                expect(decoded.payload.sub).to.be.a('string');
                expect(decoded.payload.sub).to.be.eq(user._id);

                expect(decoded.payload.aud).to.be.a('string');
                expect(decoded.payload.aud).to.be.eq(user.role);

                expect(decoded.payload.jti).to.be.a('string');
                expect(decoded.payload.jti).to.be.eq('1');

                expect(decoded.payload.exp).to.be.a('number');
                expect(decoded.payload.iat).to.be.a('number');
            }
        });
    });

    describe('GenerateID', () => {
        it('should generate random string with length of 24', () => {
            const service = new AuthenticationService();
            const id = service.generateID(24);
            expect(id).to.be.a('string');
            expect(id).to.have.lengthOf(24);
        });

        it('should generate unique id each time', () => {
            const service = new AuthenticationService();
            const ids = [];
            for (let i = 0; i < 1000; i++) {
                const id = service.generateID(24);
                expect(id).to.be.a('string');
                expect(id).to.have.lengthOf(24);
                ids.push(id);
            }
            expect(new Set(ids).size).to.be.eq(ids.length);
        });
    });

    describe('GenerateRefreshToken', () => {
        it('should generate access token', async () => {
            const service = new AuthenticationService({secret: 'secret'});
            const data = await service.generateAccessToken('123', 'user-id', 'ADMIN', '1m');
            expect(data).to.be.a('string');
        });
    });

    describe('Authenticate', () => {
        it('should authenticate', async () => {
            const now = Date.now();
            const service = new AuthenticationService({secret: 'secret'});
            const tokens = await service.authenticate('123', Role.ADMIN, '1m', '5m');

            expect(tokens).to.be.an('object');
            expect(tokens).to.have.keys(['accessToken', 'refreshToken']);

            expect(tokens.accessToken).to.be.an('object');
            expect(tokens.accessToken).to.have.keys(['token', 'tokenType', 'expiresAt']);
            expect(tokens.accessToken.token).to.be.a('string');
            expect(tokens.accessToken.tokenType).to.be.a('string');
            expect(tokens.accessToken.expiresAt).to.be.a('number');
            expect(new Date(tokens.accessToken.expiresAt)).to.be.a('date');
            expect(tokens.accessToken.expiresAt * 1000).to.be.gt(now);

            expect(tokens.refreshToken).to.be.an('object');
            expect(tokens.refreshToken).to.have.keys(['token', 'tokenType', 'expiresAt', 'notBefore']);
            expect(tokens.refreshToken.token).to.be.a('string');
            expect(tokens.refreshToken.tokenType).to.be.a('string');

            expect(tokens.refreshToken.expiresAt).to.be.a('number');
            expect(new Date(tokens.refreshToken.expiresAt)).to.be.a('date');
            expect(tokens.refreshToken.expiresAt * 1000).to.be.gt(now);

            expect(tokens.refreshToken.notBefore).to.be.a('number');
            expect(new Date(tokens.refreshToken.notBefore)).to.be.a('date');
            expect(tokens.refreshToken.notBefore * 1000).to.be.gt(now);

            expect(tokens.refreshToken.expiresAt).to.be.gt(tokens.refreshToken.notBefore);
            expect(tokens.refreshToken.notBefore).to.be.gte(tokens.accessToken.expiresAt);
        });
    });
});
