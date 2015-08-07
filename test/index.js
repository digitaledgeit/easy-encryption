var assert    = require('assert');
var cipher    = require('..');

describe('easy-encryption', function() {

  describe('.salt()', function() {

    it('should return a buffer', function() {
      assert(cipher().salt() instanceof Buffer);
    });

    it('should never return the same value', function() {
      assert.notEqual(
        cipher().salt().toString('hex'),
        cipher().salt().toString('hex')
      );
    });

  });

  describe('.hash()', function() {

    it('should return a buffer', function() {
      var c = cipher();
      assert(c.hash(c.salt(), 'password') instanceof Buffer);
    });

    it('should be 32 bytes in length', function() {
      var c = cipher(), salt = c.salt();
      assert.equal(
        c.hash(salt, 'password').length,
        32
      );
    });

    it('same salt and password should return the same hash', function() {
      var c = cipher(), salt = c.salt();
      assert.equal(
        c.hash(salt, 'password').toString('hex'),
        c.hash(salt, 'password').toString('hex')
      );
    });

    it('same salt and different password should return a different hash', function() {
      var c = cipher(), salt = c.salt();
      assert.notEqual(
        c.hash(salt, 'password1').toString('hex'),
        c.hash(salt, 'password2').toString('hex')
      );
    });

    it('same password and different salt should return a different hash', function() {
      var c = cipher();
      assert.notEqual(
        c.hash(c.salt(), 'password').toString('hex'),
        c.hash(c.salt(), 'password').toString('hex')
      );
    });

  });

  describe('.encrypt()', function() {

    it('should produce an output string made up of three parts - the IV, salt and cipher text', function() {
      assert.equal(cipher().encrypt('password', 'This message is TOP secret!!!').split('$').length, 3);
    });

    it('the same password and plain text should never produce the same output string', function() {
      assert.notEqual(
        cipher().encrypt('password', 'This message is TOP secret!!!'),
        cipher().encrypt('password', 'This message is TOP secret!!!')
      );
    });

    it('should use default password');

  });

  describe('.decrypt()', function() {

    it('unsafe cipher text should be decoded', function() {
      assert.equal(
        cipher().decrypt(
          'password',
          'fbeec170dbba9691d4df6bd706093a7a0a143d18ca936cec838e8deca332bb15'
        ),
        'This message is TOP secret!!!'
      );
    });

    it('safe cipher text should be decoded', function() {
      assert.equal(
        cipher().decrypt(
          'password',
          '46f5fdbf46f8727036b161916ce6e788$5df93a092a5ddcc05f4fb3e529a256f1208bdd7d14599b5' +
          '685debada50634a4426a42a994800f49affffd2d8775fdd87664e52301c9a8e0607ccba1ced57703' +
          '24308a32d88aab9f475c2d4725d32bcbdd1a7fb53575bdf81838799100ceb9fc5f767ac6a119ad8f' +
          'd7f95732f2a1cb8b238e84f9ffd71e015876d2bcb87fc8857$5738350049341fb124a34d085bc2aa' +
          'a121452c0ab30a5a9af93dc913481d57a7'
        ),
        'This message is TOP secret!!!'
      );
    });

    it('should throw an error when the cipher text is missing a part', function() {
      assert.throws(function() {
        cipher().decrypt(
          'password',
          '5df93a092a5ddcc05f4fb3e529a256f1208bdd7d14599b5' +
          '685debada50634a4426a42a994800f49affffd2d8775fdd87664e52301c9a8e0607ccba1ced57703' +
          '24308a32d88aab9f475c2d4725d32bcbdd1a7fb53575bdf81838799100ceb9fc5f767ac6a119ad8f' +
          'd7f95732f2a1cb8b238e84f9ffd71e015876d2bcb87fc8857$5738350049341fb124a34d085bc2aa' +
          'a121452c0ab30a5a9af93dc913481d57a7'
        )
      });
    });

    it('should throw an error when the cipher text has an extra part', function() {
      assert.throws(function() {
        cipher().decrypt(
          'password',
          '46f5fdbf46f8727036b161916ce6e788$5df93a092a5ddcc05f4fb3e529a256f1208bdd7d14599b5' +
          '685debada50634a4426a42a994800f49affffd2d8775fdd87664e52301c9a8e0607ccba1ced57703' +
          '24308a32d88aab9f475c2d4725d32bcbdd1a7fb53575bdf81838799100ceb9fc5f767ac6a119ad8f' +
          'd7f95732f2a1cb8b238e84f9ffd71e015876d2bcb87fc8857$5738350049341fb124a34d085bc2aa' +
          'a121452c0ab30a5a9af93dc913481d57a7$abc'
        )
      });
    });

    it('should throw an error when the password is incorrect', function() {
      assert.throws(function() {
        cipher().decrypt(
          'incorrect-password',
          '46f5fdbf46f8727036b161916ce6e788$5df93a092a5ddcc05f4fb3e529a256f1208bdd7d14599b5' +
          '685debada50634a4426a42a994800f49affffd2d8775fdd87664e52301c9a8e0607ccba1ced57703' +
          '24308a32d88aab9f475c2d4725d32bcbdd1a7fb53575bdf81838799100ceb9fc5f767ac6a119ad8f' +
          'd7f95732f2a1cb8b238e84f9ffd71e015876d2bcb87fc8857$5738350049341fb124a34d085bc2aa' +
          'a121452c0ab30a5a9af93dc913481d57a7'
        )
      });
    });

    it('should throw an error when the cipher text is incorrect', function() {
      assert.throws(function() {
        cipher().decrypt(
          'password',
          '46f5fdbf46f8727036b161916ce6e788$5df93a092a5ddcc05f4fb3e529a256f1208bdd7d14599b5' +
          '685debada50634a4426a42a994800f49affffd2d8775fdd87664e52301c9a8e0607ccba1ced57703' +
          '24308a32d88aab9f475c2d4725d32bcbdd1a7fb53575bdf81838799100ceb9fc5f767ac6a119ad8f' +
          'd7f95732f2a1cb8b238e84f9ffd71e015876d2bcb87fc8857$x5738350049341fb124a34d085bc2aa' +
          'a121452c0ab30a5a9af93dc913481d57a7'
        )
      });
    });

    it('should use default password');

  });

});