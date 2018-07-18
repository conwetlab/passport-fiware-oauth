const assert = require('assert');
const util = require('util');
const FIWAREStrategy = require('../lib/passport-fiware-oauth/oauth2');

const CLIENT_ID = 'ABC123';
const CLIENT_SECRET = 'secret';


describe('FIWAREStrategy', () => {

    let strategy =  new FIWAREStrategy({
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET
      },function() {});

    it('should be named fiware', function () {
        expect(strategy.name).toBe('fiware');
    });

    it('should set correct headers', function() {
        let authHeaderValue = 'Basic ' + new Buffer(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64');
        expect(strategy._oauth2._customHeaders['Authorization']).toBe(authHeaderValue);
    });

    describe('strategy when providing the IdM host', () => {
        let strategyH = new FIWAREStrategy({
            clientID: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            serverURL: 'http://mycustomidm.com/'
        }, function() {});

        it('should have changed the default host', function() {
            expect(strategyH.serverURL).toBe('http://mycustomidm.com');
        });
    });

    describe('strategy when loading user profile', () => {
        let strategyP = new FIWAREStrategy({
            clientID: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            isLegacy: true
        }, function() {});

        it('should load user profile without errors', function(done) {
            strategyP._oauth2.get = function(url, accessToken, callback) {
                let body = {"organizations": [{ "id": "12", "name": "UPM", "roles": [{"id": "14", "name": "Admin"}] }],
                    "displayName": "Jared Hanson",
                    "app_id": "564",
                    "email": "example@fiware.org",
                    "id": "fiware-user-name",
                    "roles": [{"name": "provider", "id": "106"}]};
            
                callback(null, JSON.stringify(body), undefined);
            };

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
        let strategyP = new FIWAREStrategy({
            clientID: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            isLegacy: true
        }, function() {});

        it('should load user profile without errors', function(done) {
            strategyP._oauth2.get = function(url, accessToken, callback) {
                callback(new Error('something-went-wrong'));
            };

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
