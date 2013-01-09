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
                    timestamp: Date.now() / 1000,
                    nonce: 'k3k4j5',
                    method: 'GET',
                    uri: '/resource/something',
                    host: 'example.com',
                    port: 8080
                })).to.equal('');

                done();
            });
        });
    });
});

