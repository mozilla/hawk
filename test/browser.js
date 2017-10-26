'use strict';

// Load modules

const Code = require('code');
const Hawk = require('../lib');
const Hoek = require('hoek');
const Lab = require('lab');

const Browser = require('../lib/browser');


// Declare internals

const internals = {};


// Test shortcuts

const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Browser', () => {

    const credentialsFunc = function (id) {

        return {
            id,
            key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            algorithm: (id === '1' ? 'sha1' : 'sha256'),
            user: 'steve'
        };
    };

    describe('client', () => {

        describe('header()', () => {

            it('generates a header then successfully parse it (configuration)', async () => {

                const req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080
                };

                const credentials1 = credentialsFunc('123456');

                req.authorization = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data' }).header;
                expect(req.authorization).to.exist();

                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
            });

            it('generates a header then successfully parse it (node request)', async () => {

                const req = {
                    method: 'POST',
                    url: '/resource/4?filter=a',
                    headers: {
                        host: 'example.com:8080',
                        'content-type': 'text/plain;x=y'
                    }
                };

                const payload = 'some not so random text';

                const credentials1 = credentialsFunc('123456');

                const reqHeader = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
                req.headers.authorization = reqHeader.header;

                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
                expect(() => Hawk.server.authenticatePayload(payload, credentials2, artifacts, req.headers['content-type'])).to.not.throw();
            });

            it('generates a header then successfully parse it (time offset)', async () => {

                const req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080
                };

                const credentials1 = credentialsFunc('123456');

                req.authorization = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', localtimeOffsetMsec: 100000 }).header;
                expect(req.authorization).to.exist();

                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 100000 });
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
            });

            it('generates a header then successfully parse it (no server header options)', async () => {

                const req = {
                    method: 'POST',
                    url: '/resource/4?filter=a',
                    headers: {
                        host: 'example.com:8080',
                        'content-type': 'text/plain;x=y'
                    }
                };

                const payload = 'some not so random text';

                const credentials1 = credentialsFunc('123456');

                const reqHeader = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
                req.headers.authorization = reqHeader.header;

                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
                expect(() => Hawk.server.authenticatePayload(payload, credentials2, artifacts, req.headers['content-type'])).to.not.throw();

                const res = {
                    headers: {
                        'content-type': 'text/plain'
                    },
                    getResponseHeader: function (header) {

                        return res.headers[header.toLowerCase()];
                    }
                };

                res.headers['server-authorization'] = Hawk.server.header(credentials2, artifacts);
                expect(res.headers['server-authorization']).to.exist();

                expect(Browser.client.authenticate(res, credentials2, artifacts)).to.equal(true);
            });

            it('generates a header then successfully parse it (no server header)', async () => {

                const req = {
                    method: 'POST',
                    url: '/resource/4?filter=a',
                    headers: {
                        host: 'example.com:8080',
                        'content-type': 'text/plain;x=y'
                    }
                };

                const payload = 'some not so random text';

                const credentials1 = credentialsFunc('123456');

                const reqHeader = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
                req.headers.authorization = reqHeader.header;

                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
                expect(() => Hawk.server.authenticatePayload(payload, credentials2, artifacts, req.headers['content-type'])).to.not.throw();

                const res = {
                    headers: {
                        'content-type': 'text/plain'
                    },
                    getResponseHeader: function (header) {

                        return res.headers[header.toLowerCase()];
                    }
                };

                expect(Browser.client.authenticate(res, credentials2, artifacts)).to.equal(true);
            });

            it('generates a header with stale ts and successfully authenticate on second call', async () => {

                const req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080
                };

                const credentials = credentialsFunc('123456');

                Browser.utils.setNtpSecOffset(60 * 60 * 1000);
                const { header } = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials, ext: 'some-app-data' });
                req.authorization = header;
                expect(req.authorization).to.exist();

                const err = await expect(Hawk.server.authenticate(req, credentialsFunc)).to.reject('Stale timestamp');

                const res = {
                    headers: {
                        'www-authenticate': err.output.headers['WWW-Authenticate']
                    },
                    getResponseHeader: function (lookup) {

                        return res.headers[lookup.toLowerCase()];
                    }
                };

                expect(Browser.utils.getNtpSecOffset()).to.equal(60 * 60 * 1000);
                expect(Browser.client.authenticate(res, err.credentials, header.artifacts)).to.equal(true);
                expect(Browser.utils.getNtpSecOffset()).to.equal(0);

                req.authorization = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: err.credentials, ext: 'some-app-data' }).header;
                expect(req.authorization).to.exist();

                const { credentials: credentials3, artifacts: artifacts3 } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials3.user).to.equal('steve');
                expect(artifacts3.ext).to.equal('some-app-data');
            });

            it('generates a header with stale ts and successfully authenticate on second call (manual localStorage)', async () => {

                const req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080
                };

                const credentials = credentialsFunc('123456');

                const localStorage = new Browser.internals.LocalStorage();

                Browser.utils.setStorage(localStorage);

                Browser.utils.setNtpSecOffset(60 * 60 * 1000);
                const { header } = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials, ext: 'some-app-data' });
                req.authorization = header;
                expect(req.authorization).to.exist();

                const err = await expect(Hawk.server.authenticate(req, credentialsFunc)).to.reject('Stale timestamp');

                const res = {
                    headers: {
                        'www-authenticate': err.output.headers['WWW-Authenticate']
                    },
                    getResponseHeader: function (lookup) {

                        return res.headers[lookup.toLowerCase()];
                    }
                };

                expect(parseInt(localStorage.getItem('hawk_ntp_offset'))).to.equal(60 * 60 * 1000);
                expect(Browser.utils.getNtpSecOffset()).to.equal(60 * 60 * 1000);
                expect(Browser.client.authenticate(res, err.credentials, header.artifacts)).to.equal(true);
                expect(Browser.utils.getNtpSecOffset()).to.equal(0);
                expect(parseInt(localStorage.getItem('hawk_ntp_offset'))).to.equal(0);

                req.authorization = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: err.credentials, ext: 'some-app-data' }).header;
                expect(req.authorization).to.exist();

                const { credentials: credentials3, artifacts: artifacts3 } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials3.user).to.equal('steve');
                expect(artifacts3.ext).to.equal('some-app-data');
            });

            it('generates a header then fails to parse it (missing server header hash)', async () => {

                const req = {
                    method: 'POST',
                    url: '/resource/4?filter=a',
                    headers: {
                        host: 'example.com:8080',
                        'content-type': 'text/plain;x=y'
                    }
                };

                const payload = 'some not so random text';

                const credentials1 = credentialsFunc('123456');

                const reqHeader = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
                req.headers.authorization = reqHeader.header;

                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
                expect(() => Hawk.server.authenticatePayload(payload, credentials2, artifacts, req.headers['content-type'])).to.not.throw();

                const res = {
                    headers: {
                        'content-type': 'text/plain'
                    },
                    getResponseHeader: function (header) {

                        return res.headers[header.toLowerCase()];
                    }
                };

                res.headers['server-authorization'] = Hawk.server.header(credentials2, artifacts);
                expect(res.headers['server-authorization']).to.exist();

                expect(Browser.client.authenticate(res, credentials2, artifacts, { payload: 'some reply' })).to.equal(false);
            });

            it('generates a header then successfully parse it (with hash)', async () => {

                const req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080
                };

                const credentials1 = credentialsFunc('123456');

                req.authorization = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, payload: 'hola!', ext: 'some-app-data' }).header;
                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
            });

            it('generates a header then successfully parse it then validate payload', async () => {

                const req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080
                };

                const credentials1 = credentialsFunc('123456');

                req.authorization = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, payload: 'hola!', ext: 'some-app-data' }).header;
                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
                expect(() => Hawk.server.authenticatePayload('hola!', credentials2, artifacts)).to.not.throw();
                expect(() => Hawk.server.authenticatePayload('hello!', credentials2, artifacts)).to.throw('Bad payload hash');
            });

            it('generates a header then successfully parse it (app)', async () => {

                const req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080
                };

                const credentials1 = credentialsFunc('123456');

                req.authorization = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', app: 'asd23ased' }).header;
                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
                expect(artifacts.app).to.equal('asd23ased');
            });

            it('generates a header then successfully parse it (app, dlg)', async () => {

                const req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080
                };

                const credentials1 = credentialsFunc('123456');

                req.authorization = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', app: 'asd23ased', dlg: '23434szr3q4d' }).header;
                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
                expect(artifacts.app).to.equal('asd23ased');
                expect(artifacts.dlg).to.equal('23434szr3q4d');
            });

            it('generates a header then fail authentication due to bad hash', async () => {

                const req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080
                };

                const credentials1 = credentialsFunc('123456');

                req.authorization = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, payload: 'hola!', ext: 'some-app-data' }).header;
                await expect(Hawk.server.authenticate(req, credentialsFunc, { payload: 'byebye!' })).to.reject('Bad payload hash');
            });

            it('generates a header for one resource then fail to authenticate another', async () => {

                const req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080
                };

                const credentials1 = credentialsFunc('123456');

                req.authorization = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data' }).header;
                req.url = '/something/else';

                const err = await expect(Hawk.server.authenticate(req, credentialsFunc)).to.reject();
                expect(err.credentials).to.exist();
            });

            it('returns a valid authorization header (sha1)', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha1'
                };

                const { header } = Browser.client.header('http://example.net/somewhere/over/the/rainbow', 'POST', { credentials, ext: 'Bazinga!', timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about' });
                expect(header).to.equal('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="bsvY3IfUllw6V5rvk4tStEvpBhE=", ext="Bazinga!", mac="qbf1ZPG/r/e06F4ht+T77LXi5vw="');
            });

            it('returns a valid authorization header (sha256)', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                const { header } = Browser.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, ext: 'Bazinga!', timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' });
                expect(header).to.equal('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", ext="Bazinga!", mac="q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8="');
            });

            it('returns a valid authorization header (empty payload)', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha1'
                };

                const { header } = Browser.client.header('http://example.net/somewhere/over/the/rainbow', 'POST', { credentials, ext: 'Bazinga!', timestamp: 1353809207, nonce: 'Ygvqdz', payload: '' });
                expect(header).to.equal('Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"404ghL7K+hfyhByKKejFBRGgTjU=\", ext=\"Bazinga!\", mac=\"Bh1sj1DOfFRWOdi3ww52nLCJdBE=\"');
            });

            it('returns a valid authorization header (no ext)', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                const { header } = Browser.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' });
                expect(header).to.equal('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="');
            });

            it('returns a valid authorization header (null ext)', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                const { header } = Browser.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain', ext: null });
                expect(header).to.equal('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="');
            });

            it('returns a valid authorization header (uri object)', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                const uri = Browser.utils.parseUri('https://example.net/somewhere/over/the/rainbow');
                const { header } = Browser.client.header(uri, 'POST', { credentials, timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' });
                expect(header).to.equal('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="');
            });

            it('errors on missing options', () => {

                expect(() => Browser.client.header('https://example.net/somewhere/over/the/rainbow', 'POST')).to.throw('Invalid argument type');
            });

            it('errors on empty uri', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                expect(() => Browser.client.header('', 'POST', { credentials, timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' })).to.throw('Invalid argument type');
            });

            it('errors on invalid uri', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                expect(() => Browser.client.header(4, 'POST', { credentials, timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' })).to.throw('Invalid argument type');
            });

            it('errors on missing method', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                expect(() => Browser.client.header('https://example.net/somewhere/over/the/rainbow', '', { credentials, timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' })).to.throw('Invalid argument type');
            });

            it('errors on invalid method', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                expect(() => Browser.client.header('https://example.net/somewhere/over/the/rainbow', 5, { credentials, timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' })).to.throw('Invalid argument type');
            });

            it('errors on missing credentials', () => {

                expect(() => Browser.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { ext: 'Bazinga!', timestamp: 1353809207 })).to.throw('Invalid credentials');
            });

            it('errors on invalid credentials (id)', () => {

                const credentials = {
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                expect(() => Browser.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, ext: 'Bazinga!', timestamp: 1353809207 })).to.throw('Invalid credentials');
            });

            it('errors on invalid credentials (key)', () => {

                const credentials = {
                    id: '123456',
                    algorithm: 'sha256'
                };

                expect(() => Browser.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, ext: 'Bazinga!', timestamp: 1353809207 })).to.throw('Invalid credentials');
            });

            it('errors on invalid algorithm', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'hmac-sha-0'
                };

                expect(() => Browser.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials, payload: 'something, anything!', ext: 'Bazinga!', timestamp: 1353809207 })).to.throw('Unknown algorithm');
            });

            it('uses a pre-calculated payload hash', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                const options = { credentials, ext: 'Bazinga!', timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' };
                options.hash = Browser.crypto.calculatePayloadHash(options.payload, credentials.algorithm, options.contentType);
                const { header } = Browser.client.header('https://example.net/somewhere/over/the/rainbow', 'POST', options);
                expect(header).to.equal('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", ext="Bazinga!", mac="q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8="');
            });
        });

        describe('bewit()', () => {

            it('should generate a bewit then successfully authenticate it', async () => {

                const req = {
                    method: 'GET',
                    url: '/resource/4?a=1&b=2',
                    host: 'example.com',
                    port: 80
                };

                const credentials1 = credentialsFunc('123456');

                const bewit = Browser.client.bewit('http://example.com/resource/4?a=1&b=2', { credentials: credentials1, ttlSec: 60 * 60 * 24 * 365 * 100, ext: 'some-app-data' });
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

                const bewit = Browser.client.bewit('http://example.com/resource/4?a=1&b=2', { credentials: credentials1, ttlSec: 60 * 60 * 24 * 365 * 100 });
                req.url += '&bewit=' + bewit;

                const { credentials: credentials2 } = await Hawk.uri.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
            });

            it('returns a valid bewit value', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                const bewit = Browser.client.bewit('https://example.com/somewhere/over/the/rainbow', { credentials, ttlSec: 300, localtimeOffsetMsec: 1356420407232 - Hawk.utils.now(), ext: 'xandyandz' });
                expect(bewit).to.equal('MTIzNDU2XDEzNTY0MjA3MDdca3NjeHdOUjJ0SnBQMVQxekRMTlBiQjVVaUtJVTl0T1NKWFRVZEc3WDloOD1ceGFuZHlhbmR6');
            });

            it('returns a valid bewit value (explicit HTTP port)', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                const bewit = Browser.client.bewit('http://example.com:8080/somewhere/over/the/rainbow', { credentials, ttlSec: 300, localtimeOffsetMsec: 1356420407232 - Hawk.utils.now(), ext: 'xandyandz' });
                expect(bewit).to.equal('MTIzNDU2XDEzNTY0MjA3MDdcaFpiSjNQMmNLRW80a3kwQzhqa1pBa1J5Q1p1ZWc0V1NOYnhWN3ZxM3hIVT1ceGFuZHlhbmR6');
            });

            it('returns a valid bewit value (explicit HTTPS port)', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                const bewit = Browser.client.bewit('https://example.com:8043/somewhere/over/the/rainbow', { credentials, ttlSec: 300, localtimeOffsetMsec: 1356420407232 - Hawk.utils.now(), ext: 'xandyandz' });
                expect(bewit).to.equal('MTIzNDU2XDEzNTY0MjA3MDdcL2t4UjhwK0xSaTdvQTRnUXc3cWlxa3BiVHRKYkR4OEtRMC9HRUwvVytTUT1ceGFuZHlhbmR6');
            });

            it('returns a valid bewit value (null ext)', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                const bewit = Browser.client.bewit('https://example.com/somewhere/over/the/rainbow', { credentials, ttlSec: 300, localtimeOffsetMsec: 1356420407232 - Hawk.utils.now(), ext: null });
                expect(bewit).to.equal('MTIzNDU2XDEzNTY0MjA3MDdcSUdZbUxnSXFMckNlOEN4dktQczRKbFdJQStValdKSm91d2dBUmlWaENBZz1c');
            });

            it('errors on invalid options', () => {

                expect(() => Browser.client.bewit('https://example.com/somewhere/over/the/rainbow', 4)).to.throw('Invalid inputs');
            });

            it('errors on missing uri', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                expect(() => Browser.client.bewit('', { credentials, ttlSec: 300, localtimeOffsetMsec: 1356420407232 - Hawk.utils.now(), ext: 'xandyandz' })).to.throw('Invalid inputs');
            });

            it('errors on invalid uri', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                expect(() => Browser.client.bewit(5, { credentials, ttlSec: 300, localtimeOffsetMsec: 1356420407232 - Hawk.utils.now(), ext: 'xandyandz' })).to.throw('Invalid inputs');
            });

            it('errors on invalid credentials (id)', () => {

                const credentials = {
                    key: '2983d45yun89q',
                    algorithm: 'sha256'
                };

                expect(() => Browser.client.bewit('https://example.com/somewhere/over/the/rainbow', { credentials, ttlSec: 3000, ext: 'xandyandz' })).to.throw('Invalid credentials');
            });

            it('errors on missing credentials', () => {

                expect(() => Browser.client.bewit('https://example.com/somewhere/over/the/rainbow', { ttlSec: 3000, ext: 'xandyandz' })).to.throw('Invalid credentials');
            });

            it('errors on invalid credentials (key)', () => {

                const credentials = {
                    id: '123456',
                    algorithm: 'sha256'
                };

                expect(() => Browser.client.bewit('https://example.com/somewhere/over/the/rainbow', { credentials, ttlSec: 3000, ext: 'xandyandz' })).to.throw('Invalid credentials');
            });

            it('errors on invalid algorithm', () => {

                const credentials = {
                    id: '123456',
                    key: '2983d45yun89q',
                    algorithm: 'hmac-sha-0'
                };

                expect(() => Browser.client.bewit('https://example.com/somewhere/over/the/rainbow', { credentials, ttlSec: 300, ext: 'xandyandz' })).to.throw('Unknown algorithm');
            });

            it('errors on missing options', () => {

                expect(() => Browser.client.bewit('https://example.com/somewhere/over/the/rainbow')).to.throw('Invalid inputs');
            });
        });

        describe('authenticate()', () => {

            it('handles XMLHttpRequest request object', async () => {

                const req = {
                    method: 'POST',
                    url: '/resource/4?filter=a',
                    headers: {
                        host: 'example.com:8080',
                        'content-type': 'text/plain;x=y'
                    }
                };

                const payload = 'some not so random text';

                const credentials1 = credentialsFunc('123456');

                const reqHeader = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
                req.headers.authorization = reqHeader.header;

                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
                expect(() => Hawk.server.authenticatePayload(payload, credentials2, artifacts, req.headers['content-type'])).to.not.throw();

                const res = {
                    _headers: {
                        'content-type': 'text/plain'
                    },
                    getResponseHeader: function (header) {

                        return res._headers[header.toLowerCase()];
                    }
                };

                res._headers['server-authorization'] = Hawk.server.header(credentials2, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
                expect(res._headers['server-authorization']).to.exist();

                expect(Browser.client.authenticate(res, credentials2, artifacts, { payload: 'some reply' })).to.equal(true);
            });

            it('handles Browserify response object', async () => {

                const req = {
                    method: 'POST',
                    url: '/resource/4?filter=a',
                    headers: {
                        host: 'example.com:8080',
                        'content-type': 'text/plain;x=y'
                    }
                };

                const payload = 'some not so random text';

                const credentials1 = credentialsFunc('123456');

                const reqHeader = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
                req.headers.authorization = reqHeader.header;

                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
                expect(() => Hawk.server.authenticatePayload(payload, credentials2, artifacts, req.headers['content-type'])).to.not.throw();

                const res = {
                    _headers: {
                        'content-type': 'text/plain'
                    },
                    getHeader: function (header) {

                        return res._headers[header.toLowerCase()];
                    }
                };

                res._headers['server-authorization'] = Hawk.server.header(credentials2, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
                expect(res._headers['server-authorization']).to.exist();

                expect(Browser.client.authenticate(res, credentials2, artifacts, { payload: 'some reply' })).to.equal(true);
            });

            it('handles configuration response object', async () => {

                const req = {
                    method: 'POST',
                    url: '/resource/4?filter=a',
                    headers: {
                        host: 'example.com:8080',
                        'content-type': 'text/plain;x=y'
                    }
                };

                const payload = 'some not so random text';

                const credentials1 = credentialsFunc('123456');

                const reqHeader = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
                req.headers.authorization = reqHeader.header;

                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
                expect(() => Hawk.server.authenticatePayload(payload, credentials2, artifacts, req.headers['content-type'])).to.not.throw();

                const res = {
                    headers: {
                        'content-type': 'text/plain'
                    }
                };

                res.headers['server-authorization'] = Hawk.server.header(credentials2, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
                expect(res.headers['server-authorization']).to.exist();

                expect(Browser.client.authenticate(res, credentials2, artifacts, { payload: 'some reply' })).to.equal(true);
            });

            it('handles Fetch api response object', async () => {

                const req = {
                    method: 'POST',
                    url: '/resource/4?filter=a',
                    headers: {
                        host: 'example.com:8080',
                        'content-type': 'text/plain;x=y'
                    }
                };

                const payload = 'some not so random text';

                const credentials1 = credentialsFunc('123456');

                const reqHeader = Browser.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
                req.headers.authorization = reqHeader.header;

                const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
                expect(artifacts.ext).to.equal('some-app-data');
                expect(() => Hawk.server.authenticatePayload(payload, credentials2, artifacts, req.headers['content-type'])).to.not.throw();

                const res = {
                    headers: {
                        get: (name) => res.headers[name.toLowerCase()],
                        'content-type': 'text/plain'
                    }
                };

                res.headers['server-authorization'] = Hawk.server.header(credentials2, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
                expect(res.headers['server-authorization']).to.exist();

                expect(Browser.client.authenticate(res, credentials2, artifacts, { payload: 'some reply' })).to.equal(true);
            });

            it('skips tsm validation when missing ts', () => {

                const res = {
                    headers: {
                        'www-authenticate': 'Hawk error="Stale timestamp"'
                    },
                    getResponseHeader: function (header) {

                        return res.headers[header.toLowerCase()];
                    }
                };

                const credentials = {
                    id: '123456',
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'sha256',
                    user: 'steve'
                };

                const artifacts = {
                    ts: 1402135580,
                    nonce: 'iBRB6t',
                    method: 'GET',
                    resource: '/resource/4?filter=a',
                    host: 'example.com',
                    port: '8080',
                    ext: 'some-app-data'
                };

                expect(Browser.client.authenticate(res, credentials, artifacts)).to.equal(true);
            });

            it('returns false on invalid header', () => {

                const res = {
                    headers: {
                        'server-authorization': 'Hawk mac="abc", bad="xyz"'
                    },
                    getResponseHeader: function (header) {

                        return res.headers[header.toLowerCase()];
                    }
                };

                expect(Browser.client.authenticate(res, {})).to.equal(false);
            });

            it('returns false on invalid mac', () => {

                const res = {
                    headers: {
                        'content-type': 'text/plain',
                        'server-authorization': 'Hawk mac="_IJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'
                    },
                    getResponseHeader: function (header) {

                        return res.headers[header.toLowerCase()];
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

                expect(Browser.client.authenticate(res, credentials, artifacts)).to.equal(false);
            });

            it('returns true on ignoring hash', () => {

                const res = {
                    headers: {
                        'content-type': 'text/plain',
                        'server-authorization': 'Hawk mac="XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'
                    },
                    getResponseHeader: function (header) {

                        return res.headers[header.toLowerCase()];
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

                expect(Browser.client.authenticate(res, credentials, artifacts)).to.equal(true);
            });

            it('errors on invalid WWW-Authenticate header format', () => {

                const res = {
                    headers: {
                        'www-authenticate': 'Hawk ts="1362346425875", tsm="PhwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", x="Stale timestamp"'
                    },
                    getResponseHeader: function (header) {

                        return res.headers[header.toLowerCase()];
                    }
                };

                expect(Browser.client.authenticate(res, {})).to.equal(false);
            });

            it('errors on invalid WWW-Authenticate header format', () => {

                const credentials = {
                    id: '123456',
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'sha256',
                    user: 'steve'
                };

                const res = {
                    headers: {
                        'www-authenticate': 'Hawk ts="1362346425875", tsm="hwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", error="Stale timestamp"'
                    },
                    getResponseHeader: function (header) {

                        return res.headers[header.toLowerCase()];
                    }
                };

                expect(Browser.client.authenticate(res, credentials)).to.equal(false);
            });
        });

        describe('message()', () => {

            it('generates an authorization then successfully parse it', async () => {

                const credentials1 = credentialsFunc('123456');

                const auth = Browser.client.message('example.com', 8080, 'some message', { credentials: credentials1 });
                expect(auth).to.exist();

                const { credentials: credentials2 } = await Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc);
                expect(credentials2.user).to.equal('steve');
            });

            it('generates an authorization using custom nonce/timestamp', () => {

                const credentials = credentialsFunc('123456');

                const auth = Browser.client.message('example.com', 8080, 'some message', { credentials, nonce: 'abc123', timestamp: 1398536270957 });
                expect(auth).to.exist();
                expect(auth.nonce).to.equal('abc123');
                expect(auth.ts).to.equal(1398536270957);
            });

            it('errors on missing host', () => {

                const credentials = credentialsFunc('123456');
                expect(() => Browser.client.message(null, 8080, 'some message', { credentials })).to.throw('Invalid inputs');
            });

            it('errors on invalid host', () => {

                const credentials = credentialsFunc('123456');
                expect(() => Browser.client.message(5, 8080, 'some message', { credentials })).to.throw('Invalid inputs');
            });

            it('errors on missing port', () => {

                const credentials = credentialsFunc('123456');
                expect(() => Browser.client.message('example.com', 0, 'some message', { credentials })).to.throw('Invalid inputs');
            });

            it('errors on invalid port', () => {

                const credentials = credentialsFunc('123456');
                expect(() => Browser.client.message('example.com', 'a', 'some message', { credentials })).to.throw('Invalid inputs');
            });

            it('errors on missing message', () => {

                const credentials = credentialsFunc('123456');
                expect(() => Browser.client.message('example.com', 8080, undefined, { credentials })).to.throw('Invalid inputs');
            });

            it('errors on null message', () => {

                const credentials = credentialsFunc('123456');
                expect(() => Browser.client.message('example.com', 8080, null, { credentials })).to.throw('Invalid inputs');
            });

            it('errors on invalid message', () => {

                const credentials = credentialsFunc('123456');
                expect(() => Browser.client.message('example.com', 8080, 5, { credentials })).to.throw('Invalid inputs');
            });

            it('errors on missing credentials', () => {

                expect(() => Browser.client.message('example.com', 8080, 'some message', {})).to.throw('Invalid credentials');
            });

            it('errors on missing options', () => {

                expect(() => Browser.client.message('example.com', 8080, 'some message')).to.throw('Invalid inputs');
            });

            it('errors on invalid credentials (id)', () => {

                const credentials = credentialsFunc('123456');

                const creds = Hoek.clone(credentials);
                delete creds.id;
                expect(() => Browser.client.message('example.com', 8080, 'some message', { credentials: creds })).to.throw('Invalid credentials');
            });

            it('errors on invalid credentials (key)', () => {

                const credentials = credentialsFunc('123456');

                const creds = Hoek.clone(credentials);
                delete creds.key;
                expect(() => Browser.client.message('example.com', 8080, 'some message', { credentials: creds })).to.throw('Invalid credentials');
            });

            it('errors on invalid algorithm', () => {

                const credentials = credentialsFunc('123456');

                const creds = Hoek.clone(credentials);
                creds.algorithm = 'blah';
                expect(() => Browser.client.message('example.com', 8080, 'some message', { credentials: creds })).to.throw('Unknown algorithm');
            });
        });

        describe('authenticateTimestamp()', () => {

            it('validates a timestamp', () => {

                const credentials = credentialsFunc('123456');

                const tsm = Hawk.crypto.timestampMessage(credentials);
                expect(Browser.client.authenticateTimestamp(tsm, credentials)).to.equal(true);
            });

            it('validates a timestamp without updating local time', () => {

                const credentials = credentialsFunc('123456');

                const offset = Browser.utils.getNtpSecOffset();
                const tsm = Hawk.crypto.timestampMessage(credentials, 10000);
                expect(Browser.client.authenticateTimestamp(tsm, credentials, false)).to.equal(true);
                expect(offset).to.equal(Browser.utils.getNtpSecOffset());
            });

            it('detects a bad timestamp', () => {

                const credentials = credentialsFunc('123456');

                const tsm = Hawk.crypto.timestampMessage(credentials);
                tsm.ts = 4;
                expect(Browser.client.authenticateTimestamp(tsm, credentials)).to.equal(false);
            });
        });
    });

    describe('internals', () => {

        describe('LocalStorage', () => {

            it('goes through the full lifecycle', () => {

                const storage = new Browser.internals.LocalStorage();
                expect(storage.length).to.equal(0);
                expect(storage.getItem('a')).to.equal(null);
                storage.setItem('a', 5);
                expect(storage.length).to.equal(1);
                expect(storage.key()).to.equal('a');
                expect(storage.key(0)).to.equal('a');
                expect(storage.getItem('a')).to.equal('5');
                storage.setItem('b', 'test');
                expect(storage.key()).to.equal('a');
                expect(storage.key(0)).to.equal('a');
                expect(storage.key(1)).to.equal('b');
                expect(storage.length).to.equal(2);
                expect(storage.getItem('b')).to.equal('test');
                storage.removeItem('a');
                expect(storage.length).to.equal(1);
                expect(storage.getItem('a')).to.equal(null);
                expect(storage.getItem('b')).to.equal('test');
                storage.clear();
                expect(storage.length).to.equal(0);
                expect(storage.getItem('a')).to.equal(null);
                expect(storage.getItem('b')).to.equal(null);
            });
        });
    });

    describe('utils', () => {

        describe('setStorage()', () => {

            it('sets storage for the first time', () => {

                Browser.utils.storage = new Browser.internals.LocalStorage();        // Reset state

                expect(Browser.utils.storage.getItem('hawk_ntp_offset')).to.not.exist();
                Browser.utils.storage.setItem('test', '1');
                Browser.utils.setStorage(new Browser.internals.LocalStorage());
                expect(Browser.utils.storage.getItem('test')).to.not.exist();
                Browser.utils.storage.setItem('test', '2');
                expect(Browser.utils.storage.getItem('test')).to.equal('2');
            });
        });

        describe('setNtpSecOffset()', () => {

            it('catches localStorage errors', { parallel: false }, () => {

                const orig = Browser.utils.storage.setItem;
                const consoleOrig = console.error;
                let count = 0;
                console.error = function () {

                    if (count++ === 2) {

                        console.error = consoleOrig;
                    }
                };

                Browser.utils.storage.setItem = function () {

                    Browser.utils.storage.setItem = orig;
                    throw new Error();
                };

                expect(() => {

                    Browser.utils.setNtpSecOffset(100);
                }).not.to.throw();
            });
        });

        describe('parseAuthorizationHeader()', () => {

            it('returns null on missing header', () => {

                expect(Browser.utils.parseAuthorizationHeader()).to.equal(null);
            });

            it('returns null on bad header syntax (structure)', () => {

                expect(Browser.utils.parseAuthorizationHeader('Hawk')).to.equal(null);
            });

            it('returns null on bad header syntax (parts)', () => {

                expect(Browser.utils.parseAuthorizationHeader(' ')).to.equal(null);
            });

            it('returns null on bad scheme name', () => {

                expect(Browser.utils.parseAuthorizationHeader('Basic asdasd')).to.equal(null);
            });

            it('returns null on bad attribute value', () => {

                expect(Browser.utils.parseAuthorizationHeader('Hawk test="\t"', ['test'])).to.equal(null);
            });

            it('returns null on duplicated attribute', () => {

                expect(Browser.utils.parseAuthorizationHeader('Hawk test="a", test="b"', ['test'])).to.equal(null);
            });
        });

        describe('parseUri()', () => {

            it('returns empty object on invalid', () => {

                const uri = Browser.utils.parseUri('ftp');
                expect(uri).to.equal({ host: '', port: '', resource: '' });
            });

            it('returns empty port when unknown scheme', () => {

                const uri = Browser.utils.parseUri('ftp://example.com');
                expect(uri.port).to.equal('');
            });

            it('returns default port when missing', () => {

                const uri = Browser.utils.parseUri('http://example.com');
                expect(uri.port).to.equal('80');
            });

            it('handles unusual characters correctly', () => {

                const parts = {
                    protocol: 'http+vnd.my-extension',
                    user: 'user!$&\'()*+,;=%40my-domain.com',
                    password: 'pass!$&\'()*+,;=%40:word',
                    hostname: 'foo-bar.com',
                    port: '99',
                    pathname: '/path/%40/!$&\'()*+,;=:@/',
                    query: 'query%40/!$&\'()*+,;=:@/?',
                    fragment: 'fragm%40/!$&\'()*+,;=:@/?'
                };

                parts.userInfo = parts.user + ':' + parts.password;
                parts.authority = parts.userInfo + '@' + parts.hostname + ':' + parts.port;
                parts.relative = parts.pathname + '?' + parts.query;
                parts.resource = parts.relative + '#' + parts.fragment;
                parts.source = parts.protocol + '://' + parts.authority + parts.resource;

                const uri = Browser.utils.parseUri(parts.source);
                expect(uri.host).to.equal('foo-bar.com');
                expect(uri.port).to.equal('99');
                expect(uri.resource).to.equal(parts.pathname + '?' + parts.query);
            });

            it('handles email address in path', () => {

                const uri = Browser.utils.parseUri('https://example.com/some/email@example.com');
                expect(uri).to.equal({
                    host: 'example.com',
                    port: '443',
                    resource: '/some/email@example.com'
                });
            });
        });

        describe('base64urlEncode()', () => {

            it('should base64 URL-safe decode a string', () => {

                const str = 'https://www.google.ca/webhp?sourceid=chrome-instant&ion=1&espv=2&ie=UTF-8#q=url';
                const base64str = 'aHR0cHM6Ly93d3cuZ29vZ2xlLmNhL3dlYmhwP3NvdXJjZWlkPWNocm9tZS1pbnN0YW50Jmlvbj0xJmVzcHY9MiZpZT1VVEYtOCNxPXVybA';

                expect(Browser.utils.base64urlEncode(str)).to.equal(base64str);
            });
        });
    });

    describe('crypto', () => {

        describe('utils', () => {

            it('exposes hash methods', () => {

                expect(Browser.crypto.utils.SHA256('some message').toString(Browser.crypto.utils.enc.Base64)).to.equal('xHdXq+QCC5Fo0HdvbJFhf5KQ55CsL2zivWeHx0rYgZk=');
            });
        });
    });
});
