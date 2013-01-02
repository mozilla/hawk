// Load modules

var Chai = require('chai');
var Hawk = process.env.TEST_COV ? require('../lib-cov') : require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Chai.expect;


describe('Hawk', function () {

    describe('Uri', function () {

        var credentialsFunc = function (id, callback) {

            var credentials = {
                id: id,
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'hmac-sha-256',
                user: 'steve'
            };

            return callback(null, credentials);
        };

        it('should generate a bewit then successfully authenticate it', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?a=1&b=2'
            };

            credentialsFunc('123456', function (err, credentials) {

                var bewit = Hawk.uri.getBewit(credentials, req.url, 'example.com', 8080, 60 * 60 * 24 * 365 * 100, { ext: 'some-app-data' });
                req.url += '&bewit=' + bewit;

                Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, ext) {

                    expect(err).to.not.exist;
                    expect(credentials.user).to.equal('steve');
                    expect(ext).to.equal('some-app-data');
                    done();
                });
            });
        });

        it('should successfully authenticate a request (last param)', function (done) {

                var req = {
                    headers: {
                        host: 'example.com:8080'
                    },
                    method: 'GET',
                    url: '/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MDk5OTE1ODJcRUQ0ZHJtYytVQzAvaFpYQWR0QzVYOFlaU1NHc2pLYWhjSDVDdEhYaFJZUT1cc29tZS1hcHAtZGF0YQ'
                };

                Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, ext) {

                    expect(err).to.not.exist;
                    expect(credentials.user).to.equal('steve');
                    expect(ext).to.equal('some-app-data');
                    done();
                });
        });

        it('should successfully authenticate a request (first param)', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE1ODJcRUQ0ZHJtYytVQzAvaFpYQWR0QzVYOFlaU1NHc2pLYWhjSDVDdEhYaFJZUT1cc29tZS1hcHAtZGF0YQ&a=1&b=2'
            };

            Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, ext) {

                expect(err).to.not.exist;
                expect(credentials.user).to.equal('steve');
                expect(ext).to.equal('some-app-data');
                done();
            });
        });

        it('should successfully authenticate a request (only param)', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ'
            };

            Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, ext) {

                expect(err).to.not.exist;
                expect(credentials.user).to.equal('steve');
                expect(ext).to.equal('some-app-data');
                done();
            });
        });

        it('should fail on method other than GET', function (done) {

            credentialsFunc('123456', function (err, credentials) {

                var req = {
                    headers: {
                        host: 'example.com:8080'
                    },
                    method: 'POST',
                    url: '/resource/4?filter=a'
                };

                var exp = Math.floor(Date.now() / 1000) + 60;
                var ext = 'some-app-data';
                var mac = Hawk.crypto.calculateMAC(credentials.key, credentials.algorithm, exp, '', 'POST', req.url, 'example.com', 8080, ext);
                var bewit = credentials.id + '\\' + exp + '\\' + mac + '\\' + ext;

                req.url += '&bewit=' + Hawk.utils.base64urlEncode(bewit);

                Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, ext) {

                    expect(err).to.exist;
                    expect(err.toResponse().payload.message).to.equal('Invalid method');
                    done();
                });
            });
        });

        it('should fail on invalid host header', function (done) {

            var req = {
                headers: {
                    host: ''
                },
                method: 'GET',
                url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ'
            };

            Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, ext) {

                expect(err).to.exist;
                expect(err.toResponse().payload.message).to.equal('Invalid Host header');
                done();
            });
        });

        it('should fail on empty bewit', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?bewit='
            };

            Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, ext) {

                expect(err).to.exist;
                expect(err.toResponse().payload.message).to.equal('Missing bewit');
                done();
            });
        });

        it('should fail on invalid bewit', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?bewit=*'
            };

            Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, ext) {

                expect(err).to.exist;
                expect(err.toResponse().payload.message).to.equal('Invalid bewit encoding');
                done();
            });
        });

        it('should fail on missing bewit', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4'
            };

            Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, ext) {

                expect(err).to.exist;
                expect(err.toResponse().payload.message).to.equal('Missing bewit');
                done();
            });
        });

        it('should fail on invalid bewit structure', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?bewit=abc'
            };

            Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, ext) {

                expect(err).to.exist;
                expect(err.toResponse().payload.message).to.equal('Invalid bewit structure');
                done();
            });
        });

        it('should fail on empty bewit attribute', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?bewit=YVxcY1xk'
            };

            Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, ext) {

                expect(err).to.exist;
                expect(err.toResponse().payload.message).to.equal('Missing bewit attributes');
                done();
            });
        });

        it('should fail on expired access', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?a=1&b=2&bewit=MTIzNDU2XDEzNTY0MTg1ODNcWk1wZlMwWU5KNHV0WHpOMmRucTRydEk3NXNXTjFjeWVITTcrL0tNZFdVQT1cc29tZS1hcHAtZGF0YQ'
            };

            Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, ext) {

                expect(err).to.exist;
                expect(err.toResponse().payload.message).to.equal('Access expired');
                done();
            });
        });

        it('should fail on credentials function error', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ'
            };

            Hawk.uri.authenticate(req, function (id, callback) { callback(Hawk.error.badRequest('Boom')); }, {}, function (err, credentials, ext) {

                expect(err).to.exist;
                expect(err.toResponse().payload.message).to.equal('Boom');
                done();
            });
        });

        it('should fail on null credentials function response', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ'
            };

            Hawk.uri.authenticate(req, function (id, callback) { callback(null, null); }, {}, function (err, credentials, ext) {

                expect(err).to.exist;
                expect(err.toResponse().payload.message).to.equal('Unknown credentials');
                done();
            });
        });

        it('should fail on invalid credentials function response', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ'
            };

            Hawk.uri.authenticate(req, function (id, callback) { callback(null, {}); }, {}, function (err, credentials, ext) {

                expect(err).to.exist;
                expect(err.message).to.equal('Invalid credentials');
                done();
            });
        });

        it('should fail on invalid credentials function response (unknown algorithm)', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ'
            };

            Hawk.uri.authenticate(req, function (id, callback) { callback(null, { key: 'xxx', algorithm: 'xxx' }); }, {}, function (err, credentials, ext) {

                expect(err).to.exist;
                expect(err.message).to.equal('Unknown algorithm');
                done();
            });
        });

        it('should fail on expired access', function (done) {

            var req = {
                headers: {
                    host: 'example.com:8080'
                },
                method: 'GET',
                url: '/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ'
            };

            Hawk.uri.authenticate(req, function (id, callback) { callback(null, { key: 'xxx', algorithm: 'hmac-sha-256' }); }, {}, function (err, credentials, ext) {

                expect(err).to.exist;
                expect(err.toResponse().payload.message).to.equal('Bad mac');
                done();
            });
        });
    });

    describe('#getBewit', function () {

        it('should return a valid bewit value', function (done) {

            var credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'hmac-sha-256'
            };

            var bewit = Hawk.uri.getBewit(credentials, '/somewhere/over/the/rainbow', 'example.com', 443, 300, { localtimeOffsetMsec: 1356420407232 - Date.now(), ext: 'xandyandz' });
            expect(bewit).to.equal('MTIzNDU2XDEzNTY0MjA3MDdcT2U3TzF4ZXNSTE5GTEphODBEdGRsdlVGbURzc0RnQ0gwUDRsWWxSWWloWT1ceGFuZHlhbmR6');
            done();
        });

        it('should return an empty bewit on invalid credentials', function (done) {

            var credentials = {
                key: '2983d45yun89q',
                algorithm: 'hmac-sha-256'
            };

            var bewit = Hawk.uri.getBewit(credentials, '/somewhere/over/the/rainbow', 'example.com', 443, 300, { ext: 'xandyandz' });
            expect(bewit).to.equal('');
            done();
        });

        it('should return an empty bewit on invalid algorithm', function (done) {

            var credentials = {
                id: '123456',
                key: '2983d45yun89q',
                algorithm: 'hmac-sha-0'
            };

            var bewit = Hawk.uri.getBewit(credentials, '/somewhere/over/the/rainbow', 'example.com', 443, 300, { ext: 'xandyandz' });
            expect(bewit).to.equal('');
            done();
        });
    });
});

