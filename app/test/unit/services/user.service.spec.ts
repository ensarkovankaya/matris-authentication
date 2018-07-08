import { expect } from 'chai';
import { describe, it } from 'mocha';
import { APIResponse, IGraphQLClient, UserService } from '../../../src/services/user.service';

/**
 * Fake client for api request
 */
class FakeGraphQLClient<T> implements Partial<IGraphQLClient> {

    constructor(private response: APIResponse<T>) {
    }

    public async request(query: string, variables?: { [key: string]: any }): Promise<any> {
        return this.response;
    }

    public setHeader(key: string, value: string) {
        return this;
    }
}

class ShouldNotSucceed extends Error {
    public name = 'ShouldNotSucceed';
}

describe('User Service Test', () => {
    describe('Email-Password Check', () => {
        it('should return true', async () => {
            const response = new APIResponse<{ valid: boolean }>(200, {valid: true});
            const service = new UserService(new FakeGraphQLClient(response));
            const valid = await service.isPasswordValid('email@example.com', '12345678');
            expect(valid).to.eq(true);
        });

        it('should return false', async () => {
            const response = new APIResponse<{ valid: boolean }>(200, {valid: false});
            const service = new UserService(new FakeGraphQLClient(response));
            const valid = await service.isPasswordValid('email@example.com', '12345678');
            expect(valid).to.eq(false);
        });

        it('should raise schema error', async () => {
            try {
                const response = new APIResponse<{ valid: string }>(200, {valid: 'asd'});
                const service = new UserService(new FakeGraphQLClient(response));
                await service.isPasswordValid('email@example.com', '12345678');
                throw new ShouldNotSucceed();
            } catch (e) {
                expect(e.name).to.eq('ResponseInvalidError');
            }
        });
    });
});
