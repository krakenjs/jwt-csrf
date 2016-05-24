
import { interceptHeader } from './lib';

let token;
let HEADER_NAME = 'x-csrf-jwt';

export function setToken(newToken) {
    token = newToken;
}

export function getToken(newToken) {
    return token;
}

export function setHeaderName(name) {
    HEADER_NAME = name;
}

export function getHeaderName() {
    return HEADER_NAME;
}

export function patchXhr() {

    interceptHeader(HEADER_NAME, {

        get(value) {
            token = value;
        },

        set() {
            return token;
        }
    });
}
