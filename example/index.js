var ee = require('..');

var ciphertext  = ee.encrypt('password', 'This message is TOP secret!!!');
var plaintext   = ee.decrypt('password', ciphertext);

console.log('encrypted:', ciphertext);
console.log('decrypted:', plaintext);