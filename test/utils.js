'use strict';

const Code = require('@hapi/code');
const Hawk = require('..');
const Lab = require('@hapi/lab');

const Package = require('../package.json');


const internals = {};


const { describe, it, after } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Utils', () => {

    describe('parseHost()', () => {

        it('returns port 80 for non tls node request', () => {

            const req = {
                method: 'POST',
                url: '/resource/4?filter=a',
                headers: {
                    host: 'example.com',
                    'content-type': 'text/plain;x=y'
                }
            };

            expect(Hawk.utils.parseHost(req, 'Host').port).to.equal(80);
        });

        it('returns port 443 for non tls node request', () => {

            const req = {
                method: 'POST',
                url: '/resource/4?filter=a',
                headers: {
                    host: 'example.com',
                    'content-type': 'text/plain;x=y'
                },
                connection: {
                    encrypted: true
                }
            };

            expect(Hawk.utils.parseHost(req, 'Host').port).to.equal(443);
        });

        it('returns port 443 for non tls node request (IPv6)', () => {

            const req = {
                method: 'POST',
                url: '/resource/4?filter=a',
                headers: {
                    host: '[123:123:123]',
                    'content-type': 'text/plain;x=y'
                },
                connection: {
                    encrypted: true
                }
            };

            expect(Hawk.utils.parseHost(req, 'Host').port).to.equal(443);
        });

        it('parses IPv6 headers', () => {

            const req = {
                method: 'POST',
                url: '/resource/4?filter=a',
                headers: {
                    host: '[123:123:123]:8000',
                    'content-type': 'text/plain;x=y'
                },
                connection: {
                    encrypted: true
                }
            };

            const host = Hawk.utils.parseHost(req, 'Host');
            expect(host.port).to.equal('8000');
            expect(host.name).to.equal('[123:123:123]');
        });

        it('errors on header too long', () => {

            let long = '';
            for (let i = 0; i < 5000; ++i) {
                long += 'x';
            }

            expect(Hawk.utils.parseHost({ headers: { host: long } })).to.be.null();
        });
    });

    describe('parseAuthorizationHeader()', () => {

        it('errors on header too long', () => {

            let long = 'Scheme a="';
            for (let i = 0; i < 5000; ++i) {
                long += 'x';
            }

            long += '"';

            expect(() => Hawk.utils.parseAuthorizationHeader(long, ['a'])).to.throw('Header length too long');
        });
    });

    describe('version()', () => {

        it('returns the correct package version number', () => {

            expect(Hawk.utils.version()).to.equal(Package.version);
        });
    });

    describe('setTimeFunction()', () => {

        after(() => {

            Hawk.utils.setTimeFunction(Date.now);
        });

        it('creates the value that now() will return', () => {

            Hawk.utils.setTimeFunction(() => 269323200000);
            expect(Hawk.utils.now()).to.equal(269323200000);
        });
    });

    describe('unauthorized()', () => {

        it('returns a hawk 401', () => {

            expect(Hawk.utils.unauthorized('kaboom').output.headers['WWW-Authenticate']).to.equal('Hawk error="kaboom"');
        });

        it('supports attributes', () => {

            expect(Hawk.utils.unauthorized('kaboom', { a: 'b' }).output.headers['WWW-Authenticate']).to.equal('Hawk a="b", error="kaboom"');
        });
    });
});
