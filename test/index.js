'use strict';

const Url = require('url');

const Code = require('@hapi/code');
const Hawk = require('..');
const Lab = require('@hapi/lab');


const internals = {};


const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Hawk', () => {

    const credentialsFunc = function (id) {

        return {
            id,
            key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            algorithm: (id === '1' ? 'sha1' : 'sha256'),
            user: 'steve'
        };
    };

    it('generates a header then successfully parse it (configuration)', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?filter=a',
            host: 'example.com',
            port: 8080
        };

        const credentials1 = credentialsFunc('123456');

        req.authorization = Hawk.client.header(Url.parse('http://example.com:8080/resource/4?filter=a'), req.method, { credentials: credentials1, ext: 'some-app-data' }).header;
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

        const reqHeader = Hawk.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
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

        expect(() => Hawk.client.authenticate(res, credentials2, artifacts, { payload: 'some reply' })).to.not.throw();
    });

    it('generates a header then successfully parse it (absolute request uri)', async () => {

        const req = {
            method: 'POST',
            url: 'http://example.com:8080/resource/4?filter=a',
            headers: {
                host: 'example.com:8080',
                'content-type': 'text/plain;x=y'
            }
        };

        const payload = 'some not so random text';

        const credentials1 = credentialsFunc('123456');

        const reqHeader = Hawk.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
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

        expect(() => Hawk.client.authenticate(res, credentials2, artifacts, { payload: 'some reply' })).to.not.throw();
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

        const reqHeader = Hawk.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
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

        res.headers['server-authorization'] = Hawk.server.header(credentials2, artifacts);
        expect(res.headers['server-authorization']).to.exist();

        expect(() => Hawk.client.authenticate(res, credentials2, artifacts)).to.not.throw();
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

        const reqHeader = Hawk.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
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

        res.headers['server-authorization'] = Hawk.server.header(credentials2, artifacts);
        expect(res.headers['server-authorization']).to.exist();

        expect(() => Hawk.client.authenticate(res, credentials2, artifacts, { payload: 'some reply' })).to.throw('Missing response hash attribute');
    });

    it('generates a header then successfully parse it (with hash)', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?filter=a',
            host: 'example.com',
            port: 8080
        };

        const credentials1 = credentialsFunc('123456');

        req.authorization = Hawk.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, payload: 'hola!', ext: 'some-app-data' }).header;
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

        req.authorization = Hawk.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, payload: 'hola!', ext: 'some-app-data' }).header;
        const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
        expect(credentials2.user).to.equal('steve');
        expect(artifacts.ext).to.equal('some-app-data');
        expect(() => Hawk.server.authenticatePayload('hola!', credentials2, artifacts)).to.not.throw();
        expect(() => Hawk.server.authenticatePayload('hello!', credentials2, artifacts)).to.throw('Bad payload hash');
    });

    it('generates a header then successfully parses and validates payload', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?filter=a',
            host: 'example.com',
            port: 8080
        };

        const credentials1 = credentialsFunc('123456');

        req.authorization = Hawk.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, payload: 'hola!', ext: 'some-app-data' }).header;
        const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc, { payload: 'hola!' });
        expect(credentials2.user).to.equal('steve');
        expect(artifacts.ext).to.equal('some-app-data');
    });

    it('generates a header then successfully parse it (app)', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?filter=a',
            host: 'example.com',
            port: 8080
        };

        const credentials1 = credentialsFunc('123456');

        req.authorization = Hawk.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', app: 'asd23ased' }).header;
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

        req.authorization = Hawk.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', app: 'asd23ased', dlg: '23434szr3q4d' }).header;
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

        const credentials = credentialsFunc('123456');

        req.authorization = Hawk.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials, payload: 'hola!', ext: 'some-app-data' }).header;
        await expect(Hawk.server.authenticate(req, credentialsFunc, { payload: 'byebye!' })).to.reject('Bad payload hash');
    });

    it('generates a header for one resource then fail to authenticate another', async () => {

        const req = {
            method: 'GET',
            url: '/resource/4?filter=a',
            host: 'example.com',
            port: 8080
        };

        const credentials = credentialsFunc('123456');

        req.authorization = Hawk.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials, ext: 'some-app-data' }).header;
        req.url = '/something/else';

        const err = await expect(Hawk.server.authenticate(req, credentialsFunc)).to.reject();
        expect(err.credentials).to.exist();
    });

    it('generates a header then fails to parse it (payload tampering)', async () => {

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

        const reqHeader = Hawk.client.header('http://example.com:8080/resource/4?filter=a', req.method, { credentials: credentials1, ext: 'some-app-data', payload, contentType: req.headers['content-type'] });
        req.headers.authorization = reqHeader.header;

        const { credentials: credentials2, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);
        expect(credentials2.user).to.equal('steve');
        expect(artifacts.ext).to.equal('some-app-data');
        expect(() => Hawk.server.authenticatePayload('tampered text', credentials2, artifacts, req.headers['content-type'])).to.throw('Bad payload hash');

        const res = {
            headers: {
                'content-type': 'text/plain'
            }
        };

        res.headers['server-authorization'] = Hawk.server.header(credentials2, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
        expect(res.headers['server-authorization']).to.exist();

        expect(() => Hawk.client.authenticate(res, credentials2, artifacts, { payload: 'some reply' })).to.not.throw();
    });

});
