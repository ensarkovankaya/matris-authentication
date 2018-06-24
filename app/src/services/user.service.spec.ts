import { expect } from 'chai';
import { describe, it } from 'mocha';
import { IHttpResponse, IHttpService } from './http.service';
import { UserService } from './user.service';

/**
 * Fake http service for muck api calls
 */
class FakeHttpService implements IHttpService {

    private response: IHttpResponse;

    public setResponse(data: any, status: number = 200, statusText: string = '') {
        this.response = {
            status,
            data,
            statusText
        };
    }

    public async post(url: string, data: any, config?: any) {
        return this.response;
    }
}

describe('UserService', () => {
    it('Should Get ID', async () => {

        const httpService = new FakeHttpService();
        httpService.setResponse({
            data: {
                user: {
                    _id: '123'
                }
            }
        });

        const service = new UserService(httpService);
        service.endpoint = 'http://localhost:3000/graphql';
        const id = await service.getUserByEmail('ensar@kovankaya.com');
        console.log('ID:', id);
        expect(id).to.eq('123');
    });
});
