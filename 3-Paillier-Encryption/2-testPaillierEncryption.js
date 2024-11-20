const { Paillier } = require("./1-paillierEncryption");

/** ENCRYPTING AND DECRYPTING*/
/** 1. Alice selects p and q, prime numbers of similar bit-length*/
var p = 281062564983417584197879099904493071909n;
var q = 266887658682941094264835878405310435687n;
var paillier = new Paillier();
var { publicKey, privateKey } = paillier.generateRandomKeys(p, q);

/** 2. Bob starts the encryption process*/
var m = 10410110810811133n; // hello! in ASCII // h = 104 e = 101 l = 108 l = 108 o = 111 ! = 33
var c = paillier.encryptMessage(publicKey, m);

/** 3. Alice decrypts the ciphertext*/
var m_ = paillier.decryptCipherText(privateKey, publicKey, c);
console.log(`Paillier encryption is ${m == m_ ? "correct" : "incorrect"}`);
