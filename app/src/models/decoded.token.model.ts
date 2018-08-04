import { Role } from './role.model';

export interface IDecodedTokenModel {
    id: string;
    role: Role;
    email: string;
    iat: number;
    exp: number;
}
