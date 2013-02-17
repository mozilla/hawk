// Load modules

var Chai = require('chai');
var Hoek = require('hoek');
var Hawk = require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Chai.expect;


describe('Hawk', function () {

    describe('README', function () {

        describe('core', function () {

            var credentials = {
                id: 'dh37fgj492je',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            };

            var options = {
                timestamp: 1353832234,
                nonce: 'j4h3g2',
                ext: 'some-app-ext-data'
            };

            it('should generate a header protocol example', function (done) {

                var header = Hawk.getAuthorizationHeader(credentials, 'GET', '/resource/1?b=1&a=2', 'example.com', 8000, options);

                expect(header).to.equal('Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="');
                done();
            });

            it('should generate a normalized string protocol example', function (done) {

                var normalized = Hawk.crypto.generateNormalizedString({
                    type: 'header',
                    key: credentials.key,
                    algorithm: credentials.algorithm,
                    timestamp: options.timestamp,
                    nonce: options.nonce,
                    method: 'GET',
                    uri: '/resource?a=1&b=2',
                    host: 'example.com',
                    port: 8000,
                    ext: options.ext
                });

                expect(normalized).to.equal('hawk.1.header\n1353832234\nj4h3g2\nGET\n/resource?a=1&b=2\nexample.com\n8000\n\nsome-app-ext-data\n');
                done();
            });

            var payloadOptions = Hoek.clone(options);
            payloadOptions.payload = 'Thank you for flying Hawk';

            it('should generate a header protocol example (with payload)', function (done) {

                var header = Hawk.getAuthorizationHeader(credentials, 'POST', '/resource/1?b=1&a=2', 'example.com', 8000, payloadOptions);

                expect(header).to.equal('Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", hash="CBbyqZ/H0rd6nKdg3O9FS5uiQZ5NmgcXUPLut9heuyo=", ext="some-app-ext-data", mac="D0pHf7mKEh55AxFZ+qyiJ/fVE8uL0YgkoJjOMcOhVQU="');
                done();
            });

            it('should generate a normalized string protocol example (with payload)', function (done) {

                var normalized = Hawk.crypto.generateNormalizedString({
                    type: 'header',
                    key: credentials.key,
                    algorithm: credentials.algorithm,
                    timestamp: options.timestamp,
                    nonce: options.nonce,
                    method: 'POST',
                    uri: '/resource?a=1&b=2',
                    host: 'example.com',
                    port: 8000,
                    hash: Hawk.crypto.calculateHash(payloadOptions.payload, credentials.algorithm),
                    ext: options.ext
                });

                expect(normalized).to.equal('hawk.1.header\n1353832234\nj4h3g2\nPOST\n/resource?a=1&b=2\nexample.com\n8000\nCBbyqZ/H0rd6nKdg3O9FS5uiQZ5NmgcXUPLut9heuyo=\nsome-app-ext-data\n');
                done();
            });
        });
    });
});

