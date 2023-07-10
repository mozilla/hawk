'use strict';

const Code = require('@hapi/code');
const Hawk = require('..');
const Hoek = require('@hapi/hoek');
const Lab = require('@hapi/lab');


const internals = {};


const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Server', () => {

    const credentialsFunc = function (id) {

        return {
            id,
            key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            algorithm: (id === '1' ? 'sha1' : 'sha256'),
            user: 'steve'
        };
    };

    describe('authenticate()', () => {

        it('parses a valid authentication header (sha1)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="1", ts="1353788437", nonce="k3j4h2", mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
            };

            const { credentials } = await Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() });
            expect(credentials.user).to.equal('steve');
        });

        it('parses a valid authentication header (sha256)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/1?b=1&a=2',
                host: 'example.com',
                port: 8000,
                authorization: 'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", mac="m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=", ext="some-app-data"'
            };

            const { credentials } = await Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353832234000 - Hawk.utils.now() });
            expect(credentials.user).to.equal('steve');
        });

        it('parses a valid authentication header (host override)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                headers: {
                    host: 'example1.com:8080',
                    authorization: 'Hawk id="1", ts="1353788437", nonce="k3j4h2", mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
                }
            };

            const { credentials } = await Hawk.server.authenticate(req, credentialsFunc, { host: 'example.com', localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() });
            expect(credentials.user).to.equal('steve');
        });

        it('parses a valid authentication header (host port override)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                headers: {
                    host: 'example1.com:80',
                    authorization: 'Hawk id="1", ts="1353788437", nonce="k3j4h2", mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
                }
            };

            const { credentials } = await Hawk.server.authenticate(req, credentialsFunc, { host: 'example.com', port: 8080, localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() });
            expect(credentials.user).to.equal('steve');
        });

        it('parses a valid authentication header (POST with payload)', async () => {

            const req = {
                method: 'POST',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123456", ts="1357926341", nonce="1AwuJD", hash="qAiXIVv+yjDATneWxZP2YCTa9aHRgQdnH9b3Wc+o3dg=", ext="some-app-data", mac="UeYcj5UoTVaAWXNvJfLVia7kU3VabxCqrccXP8sUGC4="'
            };

            const { credentials } = await Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1357926341000 - Hawk.utils.now() });
            expect(credentials.user).to.equal('steve');
        });

        it('errors on missing hash', async () => {

            const req = {
                method: 'GET',
                url: '/resource/1?b=1&a=2',
                host: 'example.com',
                port: 8000,
                authorization: 'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", mac="m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=", ext="some-app-data"'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { payload: 'body', localtimeOffsetMsec: 1353832234000 - Hawk.utils.now() })).to.reject('Missing required payload hash');
        });

        it('errors on missing hash (empty payload)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/1?b=1&a=2',
                host: 'example.com',
                port: 8000,
                authorization: 'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", mac="m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=", ext="some-app-data"'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { payload: '', localtimeOffsetMsec: 1353832234000 - Hawk.utils.now() })).to.reject('Missing required payload hash');
        });

        it('errors on a stale timestamp', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123456", ts="1362337299", nonce="UzmxSs", ext="some-app-data", mac="wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w="'
            };

            const err = await expect(Hawk.server.authenticate(req, credentialsFunc)).to.reject('Stale timestamp');
            const header = err.output.headers['WWW-Authenticate'];
            const ts = header.match(/^Hawk ts\=\"(\d+)\"\, tsm\=\"([^\"]+)\"\, error=\"Stale timestamp\"$/);
            const now = Hawk.utils.now();
            expect(parseInt(ts[1], 10) * 1000).to.be.within(now - 1000, now + 1000);

            const res = {
                headers: {
                    'www-authenticate': header
                }
            };

            expect(() => Hawk.client.authenticate(res, err.credentials, err.artifacts)).to.not.throw();
        });

        it('errors on a replay', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=", ext="hello"'
            };

            const memoryCache = {};
            const options = {
                localtimeOffsetMsec: 1353788437000 - Hawk.utils.now(),
                nonceFunc: function (key, nonce, ts) {

                    if (memoryCache[key + nonce]) {
                        throw new Error();
                    }

                    memoryCache[key + nonce] = true;
                }
            };

            const { credentials } = await Hawk.server.authenticate(req, credentialsFunc, options);
            expect(credentials.user).to.equal('steve');

            await expect(Hawk.server.authenticate(req, credentialsFunc, options)).to.reject('Invalid nonce');
        });

        it('does not error on nonce collision if keys differ', async () => {

            const reqSteve = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=", ext="hello"'
            };

            const reqBob = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="456", ts="1353788437", nonce="k3j4h2", mac="LXfmTnRzrLd9TD7yfH+4se46Bx6AHyhpM94hLCiNia4=", ext="hello"'
            };

            const credentialsFuncion = function (id) {

                const credentials = {
                    '123': {
                        id,
                        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                        algorithm: (id === '1' ? 'sha1' : 'sha256'),
                        user: 'steve'
                    },
                    '456': {
                        id,
                        key: 'xrunpaw3489ruxnpa98w4rxnwerxhqb98rpaxn39848',
                        algorithm: (id === '1' ? 'sha1' : 'sha256'),
                        user: 'bob'
                    }
                };

                return credentials[id];
            };

            const memoryCache = {};
            const options = {
                localtimeOffsetMsec: 1353788437000 - Hawk.utils.now(),
                nonceFunc: function (key, nonce, ts) {

                    if (memoryCache[key + nonce]) {
                        throw new Error();
                    }

                    memoryCache[key + nonce] = true;
                }
            };

            const { credentials: credentials1 } = await Hawk.server.authenticate(reqSteve, credentialsFuncion, options);
            expect(credentials1.user).to.equal('steve');

            const { credentials: credentials2 } = await Hawk.server.authenticate(reqBob, credentialsFuncion, options);
            expect(credentials2.user).to.equal('bob');
        });

        it('errors on an invalid authentication header: wrong scheme', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Basic asdasdasdasd'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Unauthorized');
        });

        it('errors on an invalid authentication header: no scheme', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: '!@#'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Invalid header syntax');
        });

        it('errors on an missing authorization header', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080
            };

            const err = await expect(Hawk.server.authenticate(req, credentialsFunc)).to.reject();
            expect(err.isMissing).to.equal(true);
        });

        it('errors on an missing host header', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                headers: {
                    authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                }
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Invalid Host header');
        });

        it('errors on an missing authorization attribute (id)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Missing attributes');
        });

        it('errors on an missing authorization attribute (ts)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Missing attributes');
        });

        it('errors on an missing authorization attribute (nonce)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", ts="1353788437", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Missing attributes');
        });

        it('errors on an missing authorization attribute (mac)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", ext="hello"'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Missing attributes');
        });

        it('errors on an unknown authorization attribute', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", x="3", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Unknown attribute: x');
        });

        it('errors on an bad authorization header format', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123\\", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Bad header format');
        });

        it('errors on an bad authorization attribute value', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="\t", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Bad attribute value: id');
        });

        it('errors on an empty authorization attribute value', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Bad attribute value: id');
        });

        it('errors on duplicated authorization attribute key', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", id="456", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Duplicate attribute: id');
        });

        it('errors on an invalid authorization header format', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk'
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Invalid header syntax');
        });

        it('errors on an bad host header (missing host)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                headers: {
                    host: ':8080',
                    authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                }
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Invalid Host header');
        });

        it('errors on an bad host header (includes path and query)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                headers: {
                    host: 'example.com:8080/path?x=z',
                    authorization: 'Hawk'
                }
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Invalid Host header');
        });

        it('errors on an bad host header (pad port)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                headers: {
                    host: 'example.com:something',
                    authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                }
            };

            await expect(Hawk.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Invalid Host header');
        });

        it('errors on credentialsFunc error', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            const credentialsFuncion = function (id) {

                throw new Error('Unknown user');
            };

            await expect(Hawk.server.authenticate(req, credentialsFuncion, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Unknown user');
        });

        it('errors on credentialsFunc error (with credentials)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            const credentialsFuncion = function (id) {

                const error = new Error('Unknown user');
                error.credentials = { some: 'value' };
                throw error;
            };

            const err = await expect(Hawk.server.authenticate(req, credentialsFuncion, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Unknown user');
            expect(err.credentials.some).to.equal('value');
        });

        it('errors on missing credentials', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            const credentialsFuncion = function (id) {

                return null;
            };

            await expect(Hawk.server.authenticate(req, credentialsFuncion, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Unknown credentials');
        });

        it('errors on invalid credentials (id)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            const credentialsFuncion = function (id) {

                return {
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    user: 'steve'
                };
            };

            const err = await expect(Hawk.server.authenticate(req, credentialsFuncion, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Invalid credentials');
            expect(err.output.payload.message).to.equal('An internal server error occurred');
        });

        it('errors on invalid credentials (key)', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            const credentialsFuncion = function (id) {

                return {
                    id: '23434d3q4d5345d',
                    user: 'steve'
                };
            };

            const err = await expect(Hawk.server.authenticate(req, credentialsFuncion, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Invalid credentials');
            expect(err.output.payload.message).to.equal('An internal server error occurred');
        });

        it('errors on unknown credentials algorithm', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            const credentialsFuncion = function (id) {

                return {
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'hmac-sha-0',
                    user: 'steve'
                };
            };

            const err = await expect(Hawk.server.authenticate(req, credentialsFuncion, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Unknown algorithm');
            expect(err.output.payload.message).to.equal('An internal server error occurred');
        });

        it('errors on unknown bad mac', async () => {

            const req = {
                method: 'GET',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcU4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
            };

            const credentialsFuncion = function (id) {

                return {
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'sha256',
                    user: 'steve'
                };
            };

            await expect(Hawk.server.authenticate(req, credentialsFuncion, { localtimeOffsetMsec: 1353788437000 - Hawk.utils.now() })).to.reject('Bad mac');
        });
    });

    describe('header()', () => {

        it('generates header', () => {

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
                ts: '1398546787',
                nonce: 'xUwusx',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                id: '123456'
            };

            const header = Hawk.server.header(credentials, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
            expect(header).to.equal('Hawk mac=\"n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE=\", hash=\"f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=\", ext=\"response-specific\"');
        });

        it('generates header (empty payload)', () => {

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
                ts: '1398546787',
                nonce: 'xUwusx',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                id: '123456'
            };

            const header = Hawk.server.header(credentials, artifacts, { payload: '', contentType: 'text/plain', ext: 'response-specific' });
            expect(header).to.equal('Hawk mac=\"i8/kUBDx0QF+PpCtW860kkV/fa9dbwEoe/FpGUXowf0=\", hash=\"q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=\", ext=\"response-specific\"');
        });

        it('generates header (empty ext)', () => {

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
                ts: '1398546787',
                nonce: 'xUwusx',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: '',
                mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                id: '123456'
            };

            const header = Hawk.server.header(credentials, artifacts, { payload: '', contentType: 'text/plain', ext: '' });
            expect(header).to.equal('Hawk mac=\"q+fdjQv3kF56JGKLYeLzAS9dYGcvDqAXRG7MTVHAFKE=\", hash=\"q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=\"');
        });

        it('generates header (pre calculated hash)', () => {

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
                ts: '1398546787',
                nonce: 'xUwusx',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                id: '123456'
            };

            const options = { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' };
            options.hash = Hawk.crypto.calculatePayloadHash(options.payload, credentials.algorithm, options.contentType);
            const header = Hawk.server.header(credentials, artifacts, options);
            expect(header).to.equal('Hawk mac=\"n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE=\", hash=\"f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=\", ext=\"response-specific\"');
        });

        it('generates header (null ext)', () => {

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
                ts: '1398546787',
                nonce: 'xUwusx',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                id: '123456'
            };

            const header = Hawk.server.header(credentials, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: null });
            expect(header).to.equal('Hawk mac=\"6PrybJTJs20jsgBw5eilXpcytD8kUbaIKNYXL+6g0ns=\", hash=\"f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=\"');
        });

        it('errors on missing artifacts', () => {

            const credentials = {
                id: '123456',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256',
                user: 'steve'
            };

            expect(() => Hawk.server.header(credentials, null, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' })).to.throw('Invalid inputs');
        });

        it('errors on invalid artifacts', () => {

            const credentials = {
                id: '123456',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256',
                user: 'steve'
            };

            expect(() => Hawk.server.header(credentials, 5, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' })).to.throw('Invalid inputs');
        });

        it('errors on missing credentials', () => {

            const artifacts = {
                method: 'POST',
                host: 'example.com',
                port: '8080',
                resource: '/resource/4?filter=a',
                ts: '1398546787',
                nonce: 'xUwusx',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                id: '123456'
            };

            expect(() => Hawk.server.header(null, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' })).to.throw('Invalid credentials');
        });

        it('errors on invalid credentials (key)', () => {

            const credentials = {
                id: '123456',
                algorithm: 'sha256',
                user: 'steve'
            };

            const artifacts = {
                method: 'POST',
                host: 'example.com',
                port: '8080',
                resource: '/resource/4?filter=a',
                ts: '1398546787',
                nonce: 'xUwusx',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                id: '123456'
            };

            expect(() => Hawk.server.header(credentials, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' })).to.throw('Invalid credentials');
        });

        it('errors on invalid credentials (algorithm)', () => {

            const credentials = {
                id: '123456',
                key: 'asdasd',
                user: 'steve'
            };

            const artifacts = {
                method: 'POST',
                host: 'example.com',
                port: '8080',
                resource: '/resource/4?filter=a',
                ts: '1398546787',
                nonce: 'xUwusx',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                id: '123456'
            };

            expect(() => Hawk.server.header(credentials, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' })).to.throw('Invalid credentials');
        });

        it('errors on invalid algorithm', () => {

            const credentials = {
                id: '123456',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'x',
                user: 'steve'
            };

            const artifacts = {
                method: 'POST',
                host: 'example.com',
                port: '8080',
                resource: '/resource/4?filter=a',
                ts: '1398546787',
                nonce: 'xUwusx',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                id: '123456'
            };

            expect(() => Hawk.server.header(credentials, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' })).to.throw('Unknown algorithm');
        });

        it('errors on invalid options', () => {

            const credentials = {
                id: '123456',
                algorithm: 'sha256',
                user: 'steve'
            };

            const artifacts = {
                method: 'POST',
                host: 'example.com',
                port: '8080',
                resource: '/resource/4?filter=a',
                ts: '1398546787',
                nonce: 'xUwusx',
                hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                ext: 'some-app-data',
                mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                id: '123456'
            };

            expect(() => Hawk.server.header(credentials, artifacts, 'abc')).to.throw('Invalid inputs');
        });
    });

    describe('authenticateBewit()', () => {

        it('errors on uri too long', async () => {

            let long = '/';
            for (let i = 0; i < 5000; ++i) {
                long += 'x';
            }

            const req = {
                method: 'GET',
                url: long,
                host: 'example.com',
                port: 8080,
                authorization: 'Hawk id="1", ts="1353788437", nonce="k3j4h2", mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
            };

            const err = await expect(Hawk.server.authenticateBewit(req, credentialsFunc, {})).to.reject('Resource path exceeds max length');
            expect(err.output.statusCode).to.equal(400);
        });
    });

    describe('authenticateMessage()', () => {

        it('errors on invalid authorization (ts)', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            delete auth.ts;

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc)).to.reject('Invalid authorization');
        });

        it('errors on invalid authorization (mac)', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            delete auth.mac;

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc)).to.reject('Invalid authorization');
        });

        it('errors on invalid authorization (nonce)', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            delete auth.nonce;

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc)).to.reject('Invalid authorization');
        });

        it('errors on invalid authorization (hash)', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            delete auth.hash;

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc)).to.reject('Invalid authorization');
        });

        it('errors with credentials', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });

            const err = await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, (id) => {

                const error = new Error('something');
                error.credentials = { some: 'value' };
                throw error;
            })).to.reject('something');
            expect(err.credentials.some).to.equal('value');
        });

        it('errors on nonce collision', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });

            const nonceFunc = function (key, nonce, ts) {

                throw new Error();
            };

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc, { nonceFunc })).to.reject('Invalid nonce');
        });

        it('should generate an authorization then successfully parse it', async () => {

            const credentials1 = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials: credentials1 });
            expect(auth).to.exist();

            const { credentials: credentials2 } = await Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc);
            expect(credentials2.user).to.equal('steve');
        });

        it('should fail authorization on mismatching host', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            expect(auth).to.exist();

            await expect(Hawk.server.authenticateMessage('example1.com', 8080, 'some message', auth, credentialsFunc)).to.reject('Bad mac');
        });

        it('should fail authorization on stale timestamp', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            expect(auth).to.exist();

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc, { localtimeOffsetMsec: 100000 })).to.reject('Stale timestamp');
        });

        it('overrides timestampSkewSec', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials, localtimeOffsetMsec: 100000 });
            expect(auth).to.exist();

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc, { timestampSkewSec: 500 })).to.not.reject();
        });

        it('should fail authorization on invalid authorization', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            expect(auth).to.exist();
            delete auth.id;

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc)).to.reject('Invalid authorization');
        });

        it('should fail authorization on bad hash', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            expect(auth).to.exist();

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message1', auth, credentialsFunc)).to.reject('Bad message hash');
        });

        it('should fail authorization on nonce error', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            expect(auth).to.exist();

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc, {
                nonceFunc: function (key, nonce, ts) {

                    throw new Error('kaboom');
                }
            })).to.reject('Invalid nonce');
        });

        it('should fail authorization on credentials error', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            expect(auth).to.exist();

            const errFunc = function (id) {

                throw new Error('kablooey');
            };

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, errFunc)).to.reject('kablooey');
        });

        it('should fail authorization on missing credentials', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            expect(auth).to.exist();

            const errFunc = function (id) { };
            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, errFunc)).to.reject('Unknown credentials');
        });

        it('should fail authorization on invalid credentials', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            expect(auth).to.exist();

            const errFunc = function (id) {

                return {};
            };

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, errFunc)).to.reject('Invalid credentials');
        });

        it('should fail authorization on invalid credentials (algorithm)', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            expect(auth).to.exist();

            const errFunc = function (id) {

                return { key: 'asdasd' };
            };

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, errFunc)).to.reject('Invalid credentials');
        });

        it('should fail authorization on invalid credentials algorithm', async () => {

            const credentials = credentialsFunc('123456');
            const auth = Hawk.client.message('example.com', 8080, 'some message', { credentials });
            expect(auth).to.exist();

            const errFunc = function (id) {

                return { key: '123', algorithm: '456' };
            };

            await expect(Hawk.server.authenticateMessage('example.com', 8080, 'some message', auth, errFunc)).to.reject('Unknown algorithm');
        });

        it('should fail on missing host', () => {

            const credentials = credentialsFunc('123456');
            expect(() => Hawk.client.message(null, 8080, 'some message', { credentials })).to.throw('Invalid inputs');
        });

        it('should fail on missing credentials', () => {

            expect(() => Hawk.client.message('example.com', 8080, 'some message')).to.throw('Invalid credentials');
        });

        it('should fail on invalid algorithm', () => {

            const credentials = credentialsFunc('123456');
            const creds = Hoek.clone(credentials);
            creds.algorithm = 'blah';
            expect(() => Hawk.client.message('example.com', 8080, 'some message', { credentials: creds })).to.throw('Unknown algorithm');
        });

        it('coverage for calculateMac arguments to calculatePayloadHash', async () => {

            const credentials = credentialsFunc('123456');
            const payload = 'some not so random text';
            const req = {
                method: 'POST',
                url: '/resource/4?filter=a',
                host: 'example.com',
                port: 8080,
                headers: {
                    host: 'example.com:8080',
                    'content-type': 'text/plain'
                }
            };

            const exp = Math.floor(Hawk.utils.now() / 1000) + 60;
            const ext = 'some-app-data';
            const nonce = '1AwuJD';
            const hash = Hawk.crypto.calculatePayloadHash(payload, 'sha256', req.headers['content-type']);
            const opts = {
                ts: exp,
                nonce,
                method: req.method,
                resource: req.url,
                host: req.host,
                port: req.port,
                hash,
                ext
            };
            const mac = Hawk.crypto.calculateServerMac('header', credentials, opts, payload, req.headers['content-type']);
            const header = 'Hawk id="' + credentials.id +
                '", ts="' + exp +
                '", nonce="' + nonce +
                '", hash="' + hash +
                '", ext="' + ext +
                '", mac="' + mac + '"';

            req.headers.authorization = header;
            // missing contentType
            Hawk.crypto.calculateServerMac('header', credentials, opts, payload);
            Hawk.crypto.calculateMac('header', credentials, opts);
            await expect(Hawk.server.authenticate(req, credentialsFunc)).to.not.reject();
        });

    });

    describe('authenticatePayloadHash()', () => {

        it('checks payload hash', () => {

            expect(() => Hawk.server.authenticatePayloadHash('abcdefg', { hash: 'abcdefg' })).to.not.throw();
            expect(() => Hawk.server.authenticatePayloadHash('1234567', { hash: 'abcdefg' })).to.throw('Bad payload hash');
        });
    });
});
