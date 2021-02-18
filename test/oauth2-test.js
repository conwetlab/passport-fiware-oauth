const assert = require('assert');
const util = require('util');
const proxyquire = require('proxyquire')

const CLIENT_ID = 'ABC123';
const CLIENT_SECRET = 'secret';


describe('FIWAREStrategy', () => {

    function strategy(fiwareStrategy, config) {
        if (config == null) {
            config = {
                clientID: CLIENT_ID,
                clientSecret: CLIENT_SECRET
            };
        }
        return new fiwareStrategy(config, function() {});
    };

    function requireStrategy(requestMock, config) {
        let FIWAREStrategy = proxyquire('../lib/passport-fiware-oauth/oauth2', {
            'request': requestMock
        });
        return strategy(FIWAREStrategy, config);
    }

    function requiredRawStrategy(config) {
        let FIWAREStrategy = require('../lib/passport-fiware-oauth/oauth2');
        return strategy(FIWAREStrategy, config);
    }

    it('should be named fiware', function () {
        let strategy = requiredRawStrategy();
        expect(strategy.name).toBe('fiware');
    });

    it('should set correct headers', function() {
        let strategy = requiredRawStrategy();
        let authHeaderValue = 'Basic ' + new Buffer(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64');
        expect(strategy._oauth2._customHeaders['Authorization']).toBe(authHeaderValue);
    });

    describe('strategy when providing the IdM host', () => {
        let strategyH = requiredRawStrategy({
            clientID: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            serverURL: 'http://mycustomidm.com/'
        });

        it('should have changed the default host', function() {
            expect(strategyH.serverURL).toBe('http://mycustomidm.com');
        });
    });

    describe('strategy when loading user profile', () => {

        it('should load user profile without errors', function(done) {
            let strategyP = requireStrategy((params, callback) => {
                let body = {"organizations": [{ "id": "12", "name": "UPM", "roles": [{"id": "14", "name": "Admin"}] }],
                    "displayName": "Jared Hanson",
                    "app_id": "564",
                    "email": "example@fiware.org",
                    "id": "fiware-user-name",
                    "roles": [{"name": "provider", "id": "106"}]};

                callback(null, {}, JSON.stringify(body));
            });

            let callback = (err, profile) => {
                expect(err).toBeNull();
                expect(profile.provider).toBe('fiware');
                expect(profile.id).toBe('fiware-user-name');
                expect(profile.displayName).toBe('Jared Hanson');
                expect(profile.emails[0].value).toBe('example@fiware.org');
                expect(profile.appId).toBe('564');
                expect(profile.roles[0].name).toBe("provider");
                expect(profile.roles[0].id).toBe("106");
                expect(profile.organizations[0].id).toBe("12");
                expect(profile.organizations[0].name).toBe("UPM");
                expect(profile.organizations[0].roles[0].id).toBe("14");
                expect(profile.organizations[0].roles[0].name).toBe("Admin");

                expect(typeof(profile._raw)).toBe('string');
                expect(typeof(profile._json)).toBe('object');
                done();
            };
            strategyP.userProfile('access-token', callback);
        });
    });

    describe('strategy when loading user profile and encountering an error', () => {
        it('should load user profile without errors', function(done) {
            let strategyP = requireStrategy((params, callback) => {
                callback(new Error('something-went-wrong'));
            });

            let callback = (err, profile) => {
                expect(err).not.toBeNull();
                expect(err.constructor.name).toBe('InternalOAuthError');
                expect(profile).toBeUndefined();
                done();
            };
            strategyP.userProfile('access-token', callback);
        });
    });
});
