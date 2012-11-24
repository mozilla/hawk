// Load modules

var expect = require('chai').expect;
var should = require('should');
var Hawk = process.env.TEST_COV ? require('../lib-cov/hawk') : require('../lib/hawk');


describe('Hawk', function () {

    describe('#authenticate', function () {

        var credentialsFunc = function (id, callback) {

            var credentials = {
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'hmac-sha-256',
                user: 'steve'
            };

            return callback(null, credentials);
        };

        it('should parse a valid authentication header', function (done) {

            var req = {
                headers: {
                    authorization: 'Hawk id="123", ts="1353788437", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"',
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?filter=a'
            };

            Hawk.authenticate(req, credentialsFunc, {}, function (err, isAuthenticated, credentials) {

                should.not.exist(err);
                credentials.user.should.equal('steve');
                done();
            });
        });

        it('should fail on an invalid authentication header: wrong scheme', function (done) {

            var req = {
                headers: {
                    authorization: 'Basic asdasdasdasd',
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?filter=a'
            };

            Hawk.authenticate(req, credentialsFunc, {}, function (err, isAuthenticated, credentials) {

                should.exist(err);
                err.message.should.equal('Incorrect authentication scheme');
                done();
            });
        });

        it('should fail on an missing authorization header', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?filter=a'
            };

            Hawk.authenticate(req, credentialsFunc, {}, function (err, isAuthenticated, credentials) {

                should.exist(err);
                err.message.should.equal('Missing Authorization header');
                done();
            });
        });

        it('should fail on an missing host header', function (done) {

            var req = {
                headers: {
                    authorization: 'Hawk id="123", ts="1353788437", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                },
                method: 'GET',
                url: '/resource/4?filter=a'
            };

            Hawk.authenticate(req, credentialsFunc, {}, function (err, isAuthenticated, credentials) {

                should.exist(err);
                err.message.should.equal('Missing Host header');
                done();
            });
        });

        it('should fail on an missing authorization attribute', function (done) {

            var req = {
                headers: {
                    authorization: 'Hawk ts="1353788437", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"',
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?filter=a'
            };

            Hawk.authenticate(req, credentialsFunc, {}, function (err, isAuthenticated, credentials) {

                should.exist(err);
                err.message.should.equal('Missing attributes');
                done();
            });
        });

        it('should fail on an bad host header', function (done) {

            var req = {
                headers: {
                    authorization: 'Hawk id="123", ts="1353788437", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"',
                    host: 'example.com:8080:90'
                },
                method: 'GET',
                url: '/resource/4?filter=a'
            };

            Hawk.authenticate(req, credentialsFunc, {}, function (err, isAuthenticated, credentials) {

                should.exist(err);
                err.message.should.equal('Bad Host header');
                done();
            });
        });
    });
});

