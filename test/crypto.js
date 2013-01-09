// Load modules

var Chai = require('chai');
var Hawk = process.env.TEST_COV ? require('../lib-cov') : require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Chai.expect;


describe('Hawk', function () {

    describe('Crypto', function () {

        describe('#calculateMAC', function () {

            it('should return an empty value on unknown algorithm', function (done) {

                expect(Hawk.crypto.calculateMAC({
                    header: 'core',
                    key: 'dasdfasdf',
                    algorithm: 'hmac-sha-0',
                    timestamp: Math.floor(Date.now() / 1000),
                    nonce: 'k3k4j5',
                    method: 'GET',
                    uri: '/resource/something',
                    host: 'example.com',
                    port: 8080
                })).to.equal('');

                done();
            });
        });

        describe('#generateNormalizedString', function () {

            it('should return a valid normalized string', function (done) {

                expect(Hawk.crypto.generateNormalizedString({
                    header: 'core',
                    key: 'dasdfasdf',
                    algorithm: 'hmac-sha-256',
                    timestamp: 1357747017,
                    nonce: 'k3k4j5',
                    method: 'GET',
                    uri: '/resource/something',
                    host: 'example.com',
                    port: 8080
                })).to.equal('core.1\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\n');

                done();
            });

            it('should return a valid normalized string (ext)', function (done) {

                expect(Hawk.crypto.generateNormalizedString({
                    header: 'core',
                    key: 'dasdfasdf',
                    algorithm: 'hmac-sha-256',
                    timestamp: 1357747017,
                    nonce: 'k3k4j5',
                    method: 'GET',
                    uri: '/resource/something',
                    host: 'example.com',
                    port: 8080,
                    ext: 'this is some app data'
                })).to.equal('core.1\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\nthis is some app data\n');

                done();
            });
        });
    });
});

