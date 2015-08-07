var assert    = require('assert');
var Cipher    = require('..');

describe('easy-encryption', function() {

  describe('.salt()', function() {

    it('should return a buffer', function() {
      assert(Cipher().salt() instanceof Buffer);
    });

    it('should never return the same value', function() {
      assert.notEqual(
        Cipher().salt().toString('hex'),
        Cipher().salt().toString('hex')
      );
    });

  });

  describe('.hash()', function() {

    it('should return a buffer', function() {
      var cipher = new Cipher();
      assert(cipher.hash(cipher.salt(), 'password') instanceof Buffer);
    });

    it('should be 32 bytes in length', function() {
      var cipher = new Cipher(), salt = cipher.salt();
      assert.equal(
        cipher.hash(salt, 'password').length,
        32
      );
    });

    it('same salt and password should return the same hash', function() {
      var cipher = new Cipher(), salt = cipher.salt();
      assert.equal(
        cipher.hash(salt, 'password').toString('hex'),
        cipher.hash(salt, 'password').toString('hex')
      );
    });

    it('same salt and different password should return a different hash', function() {
      var cipher = new Cipher(), salt = cipher.salt();
      assert.notEqual(
        cipher.hash(salt, 'password1').toString('hex'),
        cipher.hash(salt, 'password2').toString('hex')
      );
    });

    it('same password and different salt should return a different hash', function() {
      var cipher = new Cipher();
      assert.notEqual(
        cipher.hash(cipher.salt(), 'password').toString('hex'),
        cipher.hash(cipher.salt(), 'password').toString('hex')
      );
    });

  });

  describe('.encrypt()', function() {

    it('should produce an output string made up of three parts - the IV, salt and cipher text', function() {
      assert.equal(Cipher.encrypt('password', 'This message is TOP secret!!!').split('$').length, 3);
    });

    it('the same password and plain text should never produce the same output string', function() {
      assert.notEqual(
        Cipher.encrypt('password', 'This message is TOP secret!!!'),
        Cipher.encrypt('password', 'This message is TOP secret!!!')
      );
    });

    it('should be symmetric', function() {
      assert.equal(
        Cipher.decrypt(
          'password',
          Cipher.encrypt('password', 'This message is TOP secret!!!')
        ),
        'This message is TOP secret!!!'
      );
    });

  });

  describe('.decrypt()', function() {

    it('unsafe cipher text should be decoded', function() {
      assert.equal(
        Cipher.decrypt(
          'password',
          'fbeec170dbba9691d4df6bd706093a7a0a143d18ca936cec838e8deca332bb15'
        ),
        'This message is TOP secret!!!'
      );
    });

    it('safe cipher text should be decoded', function() {
      assert.equal(
        Cipher.decrypt(
          'password',
          '56b3889d36096b68775c0c12db31d119$a492fd56281e63016bfad0181a72332dde31fed4929ba74' +
          '85c13db7ad78318432b9856c9f0a92c63393600b9cbf434c47c703996a74aabb39a1738c80e36a43' +
          'fb048d54e861b43d12ee0002c3305217832229f653baf47efdfda18ecfc4fc2adb9c3b272b3ca043' +
          '292831030de5eaa85d88d6f4b065563553421f1edc24adfaf$9384bd1463a812ef89b6033bbd40a4' +
          '5b70d2776712f93cd172da2a8ddfe02c41'
        ),
        'This message is TOP secret!!!'
      );
    });

    it('should throw an error when the cipher text is missing a part', function() {
      assert.throws(function() {
        Cipher.decrypt(
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
        Cipher.decrypt(
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
        Cipher.decrypt(
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
        Cipher.decrypt(
          'password',
          '46f5fdbf46f8727036b161916ce6e788$5df93a092a5ddcc05f4fb3e529a256f1208bdd7d14599b5' +
          '685debada50634a4426a42a994800f49affffd2d8775fdd87664e52301c9a8e0607ccba1ced57703' +
          '24308a32d88aab9f475c2d4725d32bcbdd1a7fb53575bdf81838799100ceb9fc5f767ac6a119ad8f' +
          'd7f95732f2a1cb8b238e84f9ffd71e015876d2bcb87fc8857$x5738350049341fb124a34d085bc2aa' +
          'a121452c0ab30a5a9af93dc913481d57a7'
        )
      });
    });

  });

  it('should use default password if none is specified', function() {
    var cipher = new Cipher({secret: 'password'});
    assert.equal(
      cipher.decrypt(
        cipher.encrypt('This message is TOP secret!!!')
      ),
      'This message is TOP secret!!!'
    );
  });

});