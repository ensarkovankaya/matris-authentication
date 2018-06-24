import { Service } from "typedi";
import { GraphQLResponse } from '../graphql/response';
import { HttpService, IHttpResponse } from './http.service';

@Service('user.service')
export class UserService {

    private static handleResponse(res: IHttpResponse) {
        return new GraphQLResponse(res.data.data, res.data.errors);
    }

    public endpoint: string;
    private readonly config = {
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    };

    constructor(private http: HttpService = new HttpService()) {
        this.endpoint = process.env.USER_SERVICE_ENDPOINT;
    }

    public async getUserByEmail(email: string) {
        try {
            const query = `query getUser($email: String!) {
                user: get(email: $email) {
                    _id
                }
            }`;
            const result = await this.call<{ user: { '_id': string } }>(query, {email});
            result.hasErrors(true);
            return result.data.user._id;
        } catch (err) {
            console.error('UserService:GetUser', err);
            throw err;
        }
    }

    private async call<T>(query: string, variables: object): Promise<GraphQLResponse<T>> {
        if (!this.endpoint) {
            throw new Error('Endpoint undefined!');
        }
        try {
            return await this.http.post(this.endpoint, {query, variables}, this.config)
                .then(UserService.handleResponse);
        } catch (err) {
            console.error('UserService:Call', err);
            throw err;
        }
    }
}
