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

                expect(Hawk.crypto.calculateMAC('dasdfasdf', 'hmac-sha-0', Date.now() / 1000, 'k3k4j5', 'GET', '/resource/something', 'example.com', 8080)).to.equal('');
                done();
            });
        });
    });
});

