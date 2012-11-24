// Load modules

var expect = require('chai').expect;
var should = require('should');
var Hawk = require('../lib/hawk');


describe('Hawk', function () {

    describe('#authenticate', function () {

        it('should parse a valid authentication header', function (done) {

            var req = {
                headers: {
                    authentication: 'Hawk id="123", ts="1353788437", mac="", ext="hello"',
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?filter=a'
            };

            var credentialsFunc = function (id, callback) {

                var credentials = {
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'hmac-sha-256',
                    user: 'steve'
                };

                return callback(null, credentials);
            };

            Hawk.authenticate(req, encryptionPassword, {}, function (err, ticket, attributes) {

                should.not.exist(err);
                attributes.ext.should.equal('"welcome"');
                done();
            });
        });

        it('should return an error for an invalid authentication header', function (done) {

            // Note: the ticket.id already encodes all the other ticket attributes and they cannot be manually changed

            var encryptionPassword = 'example';

            var ticket = {
                id: '4deee737c1810925ace5aa5292c4e761f2325eb1286bc5c69cbf00b3f5de3abc:eL5Zvd2wyIiMc-6Adk2SUy7i4TjZKLnV_KTUYnTri5Q:a5f7aa17320716247dd18fd87f04e7c0495980b3417d94185f0feb6c052e123e:p1BY4SLSY-5fjKuPSz_GwQ:UDPFp5jLSyYZmGrlD111XxNrZzhvWdU32k_05EjPm4vi0pynvYpGGXYTuuxlEj7hwUR4BOmFumASxvZJVRMMERhCtOjqBwUbU9L8MzI2wYYEryFImSwDkxZAamsG37KH6K1w-rTP-UgP8mVpmboA9-vzwRrlaPzvV19VS7kLGEUeDR8DFzwQpMl2lK-dw4KQPPmsKSGFzxlUO-9hpvWdU6lyTdMYAoy8MPTNCMT4NbgRrjitYV-6YKmhJNHMErzs',
                key: 'wrong',
                algorithm: 'sha256',
                app: '123'
            };

            var request = {
                method: 'GET',
                resource: '/path?query',
                host: 'example.com',
                port: 80
            };

            var attributes = {
                ext: '"welcome"'
            };

            var req = {
                method: request.method,
                url: request.resource,
                headers: {
                    authorization: Oz.request.generateHeader(request, ticket, attributes),
                    host: request.host + ':' + request.port
                }
            };

            Oz.request.authenticate(req, encryptionPassword, {}, function (err, ticket, attributes) {

                should.exist(err);
                done();
            });
        });
    });
});

