import { Role } from './role.model';

export interface IAccountModel {
    id: string;
    role: Role;
    email: string;
}
