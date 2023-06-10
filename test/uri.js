'use strict';

const Url = require('url');

const B64 = require('@hapi/b64');
const Boom = require('@hapi/boom');
const Code = require('@hapi/code');
const Hawk = require('..');
const Lab = require('@hapi/lab');


const internals = {};


const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Uri', () => {

    const credentialsFunc = function (id) {

        return {
            id,
            key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            algorithm: (id === '1' ? 'sha1' : 'sha256'),
            user: 'steve'
        };
    };

    it('should generate a bewit then successfully authenticate it', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?a=1&b=2',
            host: 'example.com',
            port: 80
        };

        const credentials1 = credentialsFunc('123456');
        const bewit = Hawk.uri.getBewit('http://example.com/resource/4?a=1&b=2', { credentials: credentials1, ttlSec: 60 * 60 * 24 * 365 * 100, ext: 'some-app-data' });
        req.url += '&bewit=' + bewit;

        const { credentials: credentials2, attributes } = await Hawk.uri.authenticate(req, credentialsFunc);
        expect(credentials2.user).to.equal('steve');
        expect(attributes.ext).to.equal('some-app-data');
    });

    it('should generate a bewit then successfully authenticate it (HEAD)', async () => {

        const req = {
            method: 'HEAD',
            url: '/resource/4?a=1&b=2',
            host: 'example.com',
            port: 80
        };

        const credentials1 = credentialsFunc('123456');
        const bewit = Hawk.uri.getBewit('http://example.com/resource/4?a=1&b=2', { credentials: credentials1, ttlSec: 60 * 60 * 24 * 365 * 100, ext: 'some-app-data' });
        req.url += '&bewit=' + bewit;

        const { credentials: credentials2, attributes } = await Hawk.uri.authenticate(req, credentialsFunc);
        expect(credentials2.user).to.equal('steve');
        expect(attributes.ext).to.equal('some-app-data');
    });

    it('should generate a bewit then successfully authenticate it (no ext)', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?a=1&b=2',
            host: 'example.com',
            port: 80
        };

        const credentials1 = credentialsFunc('123456');
        const bewit = Hawk.uri.getBewit('http://example.com/resource/4?a=1&b=2', { credentials: credentials1, ttlSec: 60 * 60 * 24 * 365 * 100 });
        req.url += '&bewit=' + bewit;

        const { credentials: credentials2 } = await Hawk.uri.authenticate(req, credentialsFunc);
        expect(credentials2.user).to.equal('steve');
    });

    it('should successfully authenticate a request (last param)', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ',
            host: 'example.com',
            port: 8080
        };

        const { credentials, attributes } = await Hawk.uri.authenticate(req, credentialsFunc);
        expect(credentials.user).to.equal('steve');
        expect(attributes.ext).to.equal('some-app-data');
    });

    it('should successfully authenticate a request (first param)', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ&a=1&b=2',
            host: 'example.com',
            port: 8080
        };

        const { credentials, attributes } = await Hawk.uri.authenticate(req, credentialsFunc);
        expect(credentials.user).to.equal('steve');
        expect(attributes.ext).to.equal('some-app-data');
    });

    it('should successfully authenticate a request (only param)', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2NDFcZm1CdkNWT3MvcElOTUUxSTIwbWhrejQ3UnBwTmo4Y1VrSHpQd3Q5OXJ1cz1cc29tZS1hcHAtZGF0YQ',
            host: 'example.com',
            port: 8080
        };

        const { credentials, attributes } = await Hawk.uri.authenticate(req, credentialsFunc);
        expect(credentials.user).to.equal('steve');
        expect(attributes.ext).to.equal('some-app-data');
    });

    it('fails on multiple authentication', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2NDFcZm1CdkNWT3MvcElOTUUxSTIwbWhrejQ3UnBwTmo4Y1VrSHpQd3Q5OXJ1cz1cc29tZS1hcHAtZGF0YQ',
            host: 'example.com',
            port: 8080,
            authorization: 'Basic asdasdasdasd'
        };

        await expect(Hawk.uri.authenticate(req, credentialsFunc)).to.reject('Multiple authentications');
    });

    it('fails on method other than GET', async () => {

        const credentials = credentialsFunc('123456');

        const req = {
            method: 'POST',
            url: '/resource/4?filter=a',
            host: 'example.com',
            port: 8080
        };

        const exp = Math.floor(Hawk.utils.now() / 1000) + 60;
        const ext = 'some-app-data';
        const mac = Hawk.crypto.generateRequestMac('bewit', credentials, {
            ts: exp,
            nonce: '',
            method: req.method,
            resource: req.url,
            host: req.host,
            port: req.port,
            ext
        });

        const bewit = credentials.id + '\\' + exp + '\\' + mac + '\\' + ext;

        req.url += '&bewit=' + B64.base64urlEncode(bewit);

        await expect(Hawk.uri.authenticate(req, credentialsFunc)).to.reject('Invalid method');
    });

    it('fails on invalid host header', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            headers: {
                host: 'example.com:something'
            }
        };

        await expect(Hawk.uri.authenticate(req, credentialsFunc)).to.reject('Invalid Host header');
    });

    it('fails on empty bewit', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=',
            host: 'example.com',
            port: 8080
        };

        const err = await expect(Hawk.uri.authenticate(req, credentialsFunc)).to.reject('Empty bewit');
        expect(err.isMissing).to.not.exist();
    });

    it('fails on invalid bewit', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=*',
            host: 'example.com',
            port: 8080
        };

        const err = await expect(Hawk.uri.authenticate(req, credentialsFunc)).to.reject('Invalid bewit encoding');
        expect(err.isMissing).to.not.exist();
    });

    it('fails on missing bewit', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4',
            host: 'example.com',
            port: 8080
        };

        const err = await expect(Hawk.uri.authenticate(req, credentialsFunc)).to.reject('Unauthorized');
        expect(err.isMissing).to.equal(true);
    });

    it('fails on invalid bewit structure', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=abc',
            host: 'example.com',
            port: 8080
        };

        await expect(Hawk.uri.authenticate(req, credentialsFunc)).to.reject('Invalid bewit structure');
    });

    it('fails on empty bewit attribute', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=YVxcY1xk',
            host: 'example.com',
            port: 8080
        };

        await expect(Hawk.uri.authenticate(req, credentialsFunc)).to.reject('Missing bewit attributes');
    });

    it('fails on missing bewit id attribute', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=XDQ1NTIxNDc2MjJcK0JFbFhQMXhuWjcvd1Nrbm1ldGhlZm5vUTNHVjZNSlFVRHk4NWpTZVJ4VT1cc29tZS1hcHAtZGF0YQ',
            host: 'example.com',
            port: 8080
        };

        await expect(Hawk.uri.authenticate(req, credentialsFunc)).to.reject('Missing bewit attributes');
    });

    it('fails on missing bewit mac attribute', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=MTIzNDU2XDQ3MDkzMTY5NjNcXHNvbWUtYXBwLWRhdGE',
            host: 'example.com',
            port: 8080
        };

        await expect(Hawk.uri.authenticate(req, credentialsFunc)).to.reject('Missing bewit attributes');
    });

    it('fails on expired access', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?a=1&b=2&bewit=MTIzNDU2XDEzNTY0MTg1ODNcWk1wZlMwWU5KNHV0WHpOMmRucTRydEk3NXNXTjFjeWVITTcrL0tNZFdVQT1cc29tZS1hcHAtZGF0YQ',
            host: 'example.com',
            port: 8080
        };

        await expect(Hawk.uri.authenticate(req, credentialsFunc)).to.reject('Access expired');
    });

    it('fails on credentials function error', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            host: 'example.com',
            port: 8080
        };

        await expect(Hawk.uri.authenticate(req, (id) => {

            throw Boom.badRequest('Boom');
        })).to.reject('Boom');
    });

    it('fails on credentials function error with credentials', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            host: 'example.com',
            port: 8080
        };

        const err = await expect(Hawk.uri.authenticate(req, (id, callback) => {

            const error = Boom.badRequest('Boom');
            error.credentials = { some: 'value' };
            throw error;
        })).to.reject('Boom');
        expect(err.credentials.some).to.equal('value');
    });

    it('fails on null credentials function response', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            host: 'example.com',
            port: 8080
        };

        await expect(Hawk.uri.authenticate(req, (id) => null)).to.reject('Unknown credentials');
    });

    it('fails on invalid credentials function response', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            host: 'example.com',
            port: 8080
        };

        await expect(Hawk.uri.authenticate(req, (id) => ({}))).to.reject('Invalid credentials');
    });

    it('fails on invalid credentials function response (algorithm)', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            host: 'example.com',
            port: 8080
        };

        await expect(Hawk.uri.authenticate(req, (id) => ({ key: '123123' }))).to.reject('Invalid credentials');
    });

    it('fails on invalid credentials function response (unknown algorithm)', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            host: 'example.com',
            port: 8080
        };

        await expect(Hawk.uri.authenticate(req, (id) => ({ key: 'xxx', algorithm: 'xxx' }))).to.reject('Unknown algorithm');
    });

    it('fails on invalid credentials function response (bad mac)', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ',
            host: 'example.com',
            port: 8080
        };

        await expect(Hawk.uri.authenticate(req, (id) => ({ key: 'xxx', algorithm: 'sha256' }))).to.reject('Bad mac');
    });

    describe('getBewit()', () => {

        it('returns a valid bewit value', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            const bewit = Hawk.uri.getBewit('https://example.com/somewhere/over/the/rainbow', { credentials, ttlSec: 300, localtimeOffsetMsec: 1356420407232 - Hawk.utils.now(), ext: 'xandyandz' });
            expect(bewit).to.equal('MTIzNDU2XDEzNTY0MjA3MDdca3NjeHdOUjJ0SnBQMVQxekRMTlBiQjVVaUtJVTl0T1NKWFRVZEc3WDloOD1ceGFuZHlhbmR6');
        });

        it('returns a valid bewit value (explicit port)', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            const bewit = Hawk.uri.getBewit('https://example.com:8080/somewhere/over/the/rainbow', { credentials, ttlSec: 300, localtimeOffsetMsec: 1356420407232 - Hawk.utils.now(), ext: 'xandyandz' });
            expect(bewit).to.equal('MTIzNDU2XDEzNTY0MjA3MDdcaFpiSjNQMmNLRW80a3kwQzhqa1pBa1J5Q1p1ZWc0V1NOYnhWN3ZxM3hIVT1ceGFuZHlhbmR6');
        });

        it('returns a valid bewit value (null ext)', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            const bewit = Hawk.uri.getBewit('https://example.com/somewhere/over/the/rainbow', { credentials, ttlSec: 300, localtimeOffsetMsec: 1356420407232 - Hawk.utils.now(), ext: null });
            expect(bewit).to.equal('MTIzNDU2XDEzNTY0MjA3MDdcSUdZbUxnSXFMckNlOEN4dktQczRKbFdJQStValdKSm91d2dBUmlWaENBZz1c');
        });

        it('returns a valid bewit value (parsed uri)', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            const bewit = Hawk.uri.getBewit(Url.parse('https://example.com/somewhere/over/the/rainbow'), { credentials, ttlSec: 300, localtimeOffsetMsec: 1356420407232 - Hawk.utils.now(), ext: 'xandyandz' });
            expect(bewit).to.equal('MTIzNDU2XDEzNTY0MjA3MDdca3NjeHdOUjJ0SnBQMVQxekRMTlBiQjVVaUtJVTl0T1NKWFRVZEc3WDloOD1ceGFuZHlhbmR6');
        });

        it('errors on invalid options', () => {

            expect(() => Hawk.uri.getBewit('https://example.com/somewhere/over/the/rainbow', 4)).to.throw('Invalid inputs');
        });

        it('errors on missing options.ttlSec', () => {

            expect(() => Hawk.uri.getBewit('https://example.com/somewhere/over/the/rainbow', {})).to.throw('Invalid inputs');
        });

        it('errors on missing uri', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            expect(() => Hawk.uri.getBewit('', { credentials, ttlSec: 300, localtimeOffsetMsec: 1356420407232 - Hawk.utils.now(), ext: 'xandyandz' })).to.throw('Invalid inputs');
        });

        it('errors on invalid uri', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            expect(() => Hawk.uri.getBewit(5, { credentials, ttlSec: 300, localtimeOffsetMsec: 1356420407232 - Hawk.utils.now(), ext: 'xandyandz' })).to.throw('Invalid inputs');
        });

        it('errors on invalid credentials (id)', () => {

            const credentials = {
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            expect(() => Hawk.uri.getBewit('https://example.com/somewhere/over/the/rainbow', { credentials, ttlSec: 3000, ext: 'xandyandz' })).to.throw('Invalid credentials');
        });

        it('errors on invalid credentials (id)', () => {

            const credentials = {
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            expect(() => Hawk.uri.getBewit('https://example.com/somewhere/over/the/rainbow', { credentials, ttlSec: 3000, ext: 'xandyandz' })).to.throw('Invalid credentials');
        });

        it('errors on invalid credentials (algorithm)', () => {

            const credentials = {
                key: '2983d45yun89q',
                id: '123'
            };

            expect(() => Hawk.uri.getBewit('https://example.com/somewhere/over/the/rainbow', { credentials, ttlSec: 3000, ext: 'xandyandz' })).to.throw('Invalid credentials');
        });

        it('errors on missing credentials', () => {

            expect(() => Hawk.uri.getBewit('https://example.com/somewhere/over/the/rainbow', { ttlSec: 3000, ext: 'xandyandz' })).to.throw('Invalid credentials');
        });

        it('errors on invalid credentials (key)', () => {

            const credentials = {
                id: '123456',
                algorithm: 'sha256'
            };

            expect(() => Hawk.uri.getBewit('https://example.com/somewhere/over/the/rainbow', { credentials, ttlSec: 3000, ext: 'xandyandz' })).to.throw('Invalid credentials');
        });

        it('errors on invalid algorithm', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'hmac-sha-0'
            };

            expect(() => Hawk.uri.getBewit('https://example.com/somewhere/over/the/rainbow', { credentials, ttlSec: 300, ext: 'xandyandz' })).to.throw('Unknown algorithm');
        });

        it('errors on missing options', () => {

            expect(() => Hawk.uri.getBewit('https://example.com/somewhere/over/the/rainbow')).to.throw('Invalid inputs');
        });
    });
});
