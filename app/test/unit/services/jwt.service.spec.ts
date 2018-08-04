import { expect } from 'chai';
import { verify } from 'jsonwebtoken';
import { describe, it } from 'mocha';
import "reflect-metadata";
import { JWTService } from '../../../src/services/jwt.service';

describe('Unit -> Services -> JWTService', () => {
    it('should initialize', () => {
        const service = new JWTService();
        expect(service.configure).to.be.a('function');
        expect(service.sign).to.be.a('function');
        expect(service.verify).to.be.a('function');
        expect(service.secret).to.be.eq(undefined);
        expect(service.expiresIn).to.be.eq('1d');
    });

    it('should configure', () => {
        const service = new JWTService();
        service.configure({
            expiresIn: '1w',
            secret: 'abc'
        });
        expect(service.secret).to.be.eq('abc');
        expect(service.expiresIn).to.be.eq('1w');
    });

    it('should sign', async () => {
        const service = new JWTService();
        service.configure({
            expiresIn: '5y',
            secret: 'topsecret'
        });
        const token = await service.sign({id: '12345', email: 'mail@mail.com', role: 'ADMIN'});
        expect(token).to.be.a('string');
        expect(token.length).to.be.gte(180);
    });

    it('should verify token', async () => {
        const service = new JWTService();
        service.configure({
            expiresIn: '5y',
            secret: 'topsecret'
        });
        const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMzQ1IiwiZW1haWwiOiJt' +
        'YWlsQG1haWwuY29tIiwicm9sZSI6IkFETUlOIiwiaWF0IjoxNTMzMzgzMjUxLCJleHAiOjE2OTExNzEyNTF9.' +
        'bCZgmKjQJDGAMEUgGO5a7cgXF_rVqjpmPLzz3A1tzmg';
        const decoded = await service.verify<{
            id: string;
            email: string;
            role: string;
            iat: number;
            exp: number;
        }>(token);
        expect(decoded).to.be.an('object');
        expect(decoded).to.have.keys(['id', 'email', 'role', 'iat', 'exp']);
        expect(decoded.id).to.be.eq('12345');
        expect(decoded.email).to.be.eq('mail@mail.com');
        expect(decoded.role).to.be.eq('ADMIN');
        expect(decoded.iat).to.be.eq(1533383251);
        expect(decoded.exp).to.be.eq(1691171251);
    });
});
