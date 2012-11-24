// Load modules

var expect = require('chai').expect;
var should = require('should');
var Hawk = process.env.TEST_COV ? require('../lib-cov/hawk') : require('../lib/hawk');


describe('Hawk', function () {

    describe('#authenticate', function () {

        var credentialsFunc = function (id, callback) {

            var credentials = {
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: (id === '1' ? 'hmac-sha-1' : 'hmac-sha-256'),
                user: 'steve'
            };

            return callback(null, credentials);
        };

        it('should parse a valid authentication header (hmac-sha-1)', function (done) {

            var req = {
                headers: {
                    authorization: 'Hawk id="1", ts="1353788437", mac="lDdDLlWQhgcxTvYgzzLo3EZExog=", ext="hello"',
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

        it('should parse a valid authentication header (hmac-sha-256)', function (done) {

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

        it('should fail on credentialsFunc error', function (done) {

            var req = {
                headers: {
                    authorization: 'Hawk id="123", ts="1353788437", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"',
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?filter=a'
            };

            var credentialsFunc = function (id, callback) {

                return callback(new Error('Unknown user'));
            };

            Hawk.authenticate(req, credentialsFunc, {}, function (err, isAuthenticated, credentials) {

                should.exist(err);
                err.message.should.equal('Unknown user');
                done();
            });
        });

        it('should fail on missing credentials', function (done) {

            var req = {
                headers: {
                    authorization: 'Hawk id="123", ts="1353788437", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"',
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?filter=a'
            };

            var credentialsFunc = function (id, callback) {

                return callback(null, null);
            };

            Hawk.authenticate(req, credentialsFunc, {}, function (err, isAuthenticated, credentials) {

                should.exist(err);
                err.message.should.equal('Missing credentials');
                done();
            });
        });

        it('should fail on invalid credentials', function (done) {

            var req = {
                headers: {
                    authorization: 'Hawk id="123", ts="1353788437", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"',
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?filter=a'
            };

            var credentialsFunc = function (id, callback) {

                var credentials = {
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    user: 'steve'
                };

                return callback(null, credentials);
            };

            Hawk.authenticate(req, credentialsFunc, {}, function (err, isAuthenticated, credentials) {

                should.exist(err);
                err.message.should.equal('Invalid credentials');
                done();
            });
        });

        it('should fail on unknown credentials algorithm', function (done) {

            var req = {
                headers: {
                    authorization: 'Hawk id="123", ts="1353788437", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"',
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?filter=a'
            };

            var credentialsFunc = function (id, callback) {

                var credentials = {
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'hmac-sha-0',
                    user: 'steve'
                };

                return callback(null, credentials);
            };

            Hawk.authenticate(req, credentialsFunc, {}, function (err, isAuthenticated, credentials) {

                should.exist(err);
                err.message.should.equal('Unknown algorithm');
                done();
            });
        });

        it('should fail on unknown bad mac', function (done) {

            var req = {
                headers: {
                    authorization: 'Hawk id="123", ts="1353788437", mac="/qwS4UjfVWMcU4jlr7T/wuKe3dKijvTvSos=", ext="hello"',
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

            Hawk.authenticate(req, credentialsFunc, {}, function (err, isAuthenticated, credentials) {

                should.exist(err);
                err.message.should.equal('Bad mac');
                done();
            });
        });
    });

    describe('#getWWWAuthenticateHeader', function () {

        it('should return a valid Hawk header with error', function (done) {

            Hawk.getWWWAuthenticateHeader('boom').should.equal('Hawk error="boom"');
            done();
        });

        it('should return a valid Hawk header without error', function (done) {

            Hawk.getWWWAuthenticateHeader().should.equal('Hawk');
            done();
        });
    });
});

