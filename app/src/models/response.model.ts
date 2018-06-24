import { Location } from "express-validator/check/location";

export interface IValidationError {
    location: Location;
    param: string;
    msg: string;
}
