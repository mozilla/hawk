// Load modules

var Chai = require('chai');
var Hawk = process.env.TEST_COV ? require('../lib-cov') : require('../lib');
var Package = require('../package.json');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Chai.expect;


describe('Hawk', function () {

    describe('Utils', function () {

        describe('#version', function () {

            it('returns the correct package version number', function (done) {

                expect(Hawk.utils.version()).to.equal(Package.version);
                done();
            });
        });

        describe('#fixedTimeComparison', function () {

            var a = Hawk.utils.randomString(50000);
            var b = Hawk.utils.randomString(150000);

            it('should take the same amount of time comparing different string sizes', function (done) {

                var now = Date.now();
                Hawk.utils.fixedTimeComparison(b, a);
                var t1 = Date.now() - now;

                now = Date.now();
                Hawk.utils.fixedTimeComparison(b, b);
                var t2 = Date.now() - now;

                expect(t2 - t1).to.be.within(-1, 1);
                done();
            });

            it('should return true for equal strings', function (done) {

                expect(Hawk.utils.fixedTimeComparison(a, a)).to.equal(true);
                done();
            });

            it('should return false for different strings (size, a < b)', function (done) {

                expect(Hawk.utils.fixedTimeComparison(a, a + 'x')).to.equal(false);
                done();
            });

            it('should return false for different strings (size, a > b)', function (done) {

                expect(Hawk.utils.fixedTimeComparison(a + 'x', a)).to.equal(false);
                done();
            });

            it('should return false for different strings (size, a = b)', function (done) {

                expect(Hawk.utils.fixedTimeComparison(a + 'x', a + 'y')).to.equal(false);
                done();
            });
        });
    });
});


