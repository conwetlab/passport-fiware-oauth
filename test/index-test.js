const fiware = require('../lib/passport-fiware-oauth/index');


describe('passport-fiware-oauth', () => {
  
    it('should report a version', function () {
      expect(typeof(fiware.version)).toBe("string");
    });

    it('should export OAuth 2.0 strategy', function () {
      expect(typeof(fiware.OAuth2Strategy)).toBe("function")
    });
  
});
