'use strict';

// Load modules

const Code = require('code');
const Hawk = require('../lib');
const Lab = require('lab');


// Declare internals

const internals = {};


// Test shortcuts

const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Client', () => {

    describe('header()', () => {

        it('returns a valid authorization header (sha1)', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha1'
            };

            const { header } = Hawk.client.header('http://example.net/somewhere/over/the/rainbow', 'POST', { credentials, ext: 'Bazinga!', timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about' });
            expect(header).to.equal('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="bsvY3IfUllw6V5rvk4tStEvpBhE=", ext="Bazinga!", mac="qbf1ZPG/r/e06F4ht+T77LXi5vw="');
        });

        it('returns a valid authorization header (sha256)', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            const { header } = Hawk.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, ext: 'Bazinga!', timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' });
            expect(header).to.equal('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", ext="Bazinga!", mac="q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8="');
        });

        it('returns a valid authorization header (no ext)', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            const { header } = Hawk.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' });
            expect(header).to.equal('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="');
        });

        it('returns a valid authorization header (null ext)', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            const { header } = Hawk.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain', ext: null });
            expect(header).to.equal('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="');
        });

        it('returns a valid authorization header (empty payload)', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            const { header } = Hawk.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, timestamp: 1353809207, nonce: 'Ygvqdz', payload: '', contentType: 'text/plain' });
            expect(header).to.equal('Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=\", mac=\"U5k16YEzn3UnBHKeBzsDXn067Gu3R4YaY6xOt9PYRZM=\"');
        });

        it('returns a valid authorization header (pre hashed payload)', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            const options = { credentials, timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' };
            options.hash = Hawk.crypto.calculatePayloadHash(options.payload, credentials.algorithm, options.contentType);
            const { header } = Hawk.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', options);
            expect(header).to.equal('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="');
        });

        it('errors on missing uri', () => {

            expect(() => Hawk.client.header('', 'POST')).to.throw('Invalid argument type');
        });

        it('errors on invalid uri', () => {

            expect(() => Hawk.client.header(4, 'POST')).to.throw('Invalid argument type');
        });

        it('errors on missing method', () => {

            expect(() => Hawk.client.header('https://example.net/somewhere/over/the/rainbow', '')).to.throw('Invalid argument type');
        });

        it('errors on invalid method', () => {

            expect(() => Hawk.client.header('https://example.net/somewhere/over/the/rainbow', 5)).to.throw('Invalid argument type');
        });

        it('errors on missing options', () => {

            expect(() => Hawk.client.header('https://example.net/somewhere/over/the/rainbow', 'POST')).to.throw('Invalid argument type');
        });

        it('errors on invalid credentials (id)', () => {

            const credentials = {
                key: '2983d45yun89q',
                algorithm: 'sha256'
            };

            expect(() => Hawk.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, ext: 'Bazinga!', timestamp: 1353809207 })).to.throw('Invalid credentials');
        });

        it('errors on missing credentials', () => {

            expect(() => Hawk.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { ext: 'Bazinga!', timestamp: 1353809207 })).to.throw('Invalid credentials');
        });

        it('errors on invalid credentials', () => {

            const credentials = {
                id: '123456',
                algorithm: 'sha256'
            };

            expect(() => Hawk.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, ext: 'Bazinga!', timestamp: 1353809207 })).to.throw('Invalid credentials');
        });

        it('errors on invalid algorithm', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'hmac-sha-0'
            };

            expect(() => Hawk.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, payload: 'something, anything!', ext: 'Bazinga!', timestamp: 1353809207 })).to.throw('Unknown algorithm');
        });
    });

    describe('authenticate()', () => {

        it('rejects on invalid header', () => {

            const res = {
                headers: {
                    'server-authorization': 'Hawk mac="abc", bad="xyz"'
                }
            };

            expect(() => Hawk.client.authenticate(res)).to.throw('Invalid Server-Authorization header');
        });

        it('rejects on invalid mac', () => {

            const res = {
                headers: {
                    'content-type': 'text/plain',
                    'server-authorization': 'Hawk mac="_IJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'
                }
            };

            const artifacts = {
                method: 'POST',
                host: 'example.com',
                port: '8080',
                resource: '/resource/4?filter=a',
                ts: '1362336900',
                nonce: 'eb5S_L',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                app: undefined,
                dlg: undefined,
                mac: 'BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk=',
                id: '123456'
            };

            const credentials = {
                id: '123456',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256',
                user: 'steve'
            };

            expect(() => Hawk.client.authenticate(res, credentials, artifacts)).to.throw('Bad response mac');
        });

        it('returns headers on ignoring hash', () => {

            const res = {
                headers: {
                    'content-type': 'text/plain',
                    'server-authorization': 'Hawk mac="XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'
                }
            };

            const artifacts = {
                method: 'POST',
                host: 'example.com',
                port: '8080',
                resource: '/resource/4?filter=a',
                ts: '1362336900',
                nonce: 'eb5S_L',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                app: undefined,
                dlg: undefined,
                mac: 'BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk=',
                id: '123456'
            };

            const credentials = {
                id: '123456',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256',
                user: 'steve'
            };

            const { headers } = Hawk.client.authenticate(res, credentials, artifacts);
            expect(headers).to.equal({
                'server-authorization': {
                    mac: 'XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=',
                    hash: 'f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=',
                    ext: 'response-specific'
                }
            });
        });

        it('validates response payload', () => {

            const payload = 'some reply';

            const res = {
                headers: {
                    'content-type': 'text/plain',
                    'server-authorization': 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'
                }
            };

            const credentials = {
                id: '123456',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256',
                user: 'steve'
            };

            const artifacts = {
                method: 'POST',
                host: 'example.com',
                port: '8080',
                resource: '/resource/4?filter=a',
                ts: '1453070933',
                nonce: '3hOHpR',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                app: undefined,
                dlg: undefined,
                mac: '/DitzeD66F2f7O535SERbX9p+oh9ZnNLqSNHG+c7/vs=',
                id: '123456'
            };

            const { headers } = Hawk.client.authenticate(res, credentials, artifacts, { payload });
            expect(headers).to.equal({
                'server-authorization': {
                    mac: 'odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=',
                    hash: 'f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=',
                    ext: 'response-specific'
                }
            });
        });

        it('errors on invalid response payload', () => {

            const payload = 'wrong reply';

            const res = {
                headers: {
                    'content-type': 'text/plain',
                    'server-authorization': 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'
                }
            };

            const credentials = {
                id: '123456',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256',
                user: 'steve'
            };

            const artifacts = {
                method: 'POST',
                host: 'example.com',
                port: '8080',
                resource: '/resource/4?filter=a',
                ts: '1453070933',
                nonce: '3hOHpR',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                app: undefined,
                dlg: undefined,
                mac: '/DitzeD66F2f7O535SERbX9p+oh9ZnNLqSNHG+c7/vs=',
                id: '123456'
            };

            expect(() => Hawk.client.authenticate(res, credentials, artifacts, { payload })).to.throw('Bad response payload mac');
        });

        it('fails on invalid WWW-Authenticate header format', () => {

            const header = 'Hawk ts="1362346425875", tsm="PhwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", x="Stale timestamp"';
            expect(() => Hawk.client.authenticate({ headers: { 'www-authenticate': header } }, {})).to.throw('Invalid WWW-Authenticate header');
        });

        it('fails on invalid WWW-Authenticate header format', () => {

            const credentials = {
                id: '123456',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256',
                user: 'steve'
            };

            const header = 'Hawk ts="1362346425875", tsm="hwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", error="Stale timestamp"';
            expect(() => Hawk.client.authenticate({ headers: { 'www-authenticate': header } }, credentials)).to.throw('Invalid server timestamp hash');
        });

        it('skips tsm validation when missing ts', () => {

            const header = 'Hawk error="Stale timestamp"';
            const { headers } = Hawk.client.authenticate({ headers: { 'www-authenticate': header } });
            expect(headers).to.equal({ 'www-authenticate': { error: 'Stale timestamp' } });
        });
    });

    describe('message()', () => {

        it('generates authorization', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha1'
            };

            const auth = Hawk.client.message('example.com', 80, 'I am the boodyman', { credentials, timestamp: 1353809207, nonce: 'abc123' });
            expect(auth).to.exist();
            expect(auth.ts).to.equal(1353809207);
            expect(auth.nonce).to.equal('abc123');
        });

        it('errors on invalid host', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha1'
            };

            expect(() => Hawk.client.message(5, 80, 'I am the boodyman', { credentials, timestamp: 1353809207, nonce: 'abc123' })).to.throw('Invalid inputs');
        });

        it('errors on invalid port', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha1'
            };

            expect(() => Hawk.client.message('example.com', '80', 'I am the boodyman', { credentials, timestamp: 1353809207, nonce: 'abc123' })).to.throw('Invalid inputs');
        });

        it('errors on missing host', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha1'
            };

            expect(() => Hawk.client.message(undefined, 0, 'I am the boodyman', { credentials, timestamp: 1353809207, nonce: 'abc123' })).to.throw('Invalid inputs');
        });

        it('errors on missing port', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha1'
            };

            expect(() => Hawk.client.message('example.com', undefined, 'I am the boodyman', { credentials, timestamp: 1353809207, nonce: 'abc123' })).to.throw('Invalid inputs');
        });

        it('errors on null message', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha1'
            };

            expect(() => Hawk.client.message('example.com', 80, null, { credentials, timestamp: 1353809207, nonce: 'abc123' })).to.throw('Invalid inputs');
        });

        it('errors on missing message', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha1'
            };

            expect(() => Hawk.client.message('example.com', 80, undefined, { credentials, timestamp: 1353809207, nonce: 'abc123' })).to.throw('Invalid inputs');
        });

        it('errors on invalid message', () => {

            const credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'sha1'
            };

            expect(() => Hawk.client.message('example.com', 80, 5, { credentials, timestamp: 1353809207, nonce: 'abc123' })).to.throw('Invalid inputs');
        });

        it('errors on missing options', () => {

            expect(() => Hawk.client.message('example.com', 80, 'I am the boodyman')).to.throw('Invalid credentials');
        });

        it('errors on invalid credentials (id)', () => {

            const credentials = {
                key: '2983d45yun89q',
                algorithm: 'sha1'
            };

            expect(() => Hawk.client.message('example.com', 80, 'I am the boodyman', { credentials, timestamp: 1353809207, nonce: 'abc123' })).to.throw('Invalid credentials');
        });

        it('errors on invalid credentials (key)', () => {

            const credentials = {
                id: '123456',
                algorithm: 'sha1'
            };

            expect(() => Hawk.client.message('example.com', 80, 'I am the boodyman', { credentials, timestamp: 1353809207, nonce: 'abc123' })).to.throw('Invalid credentials');
        });
    });
});
