// https://github.com/Blockchain-Bites/two-party-computation-signature
// File: 3-Paillier-Encryption/1-paillierEncryption.js
// test: node 3-Paillier-Encryption/2-testPaillierEncryption.js

var crypto = require("crypto");

class Paillier {
  ///////////////////////////////////////////////////////////////
  ///////////////// | DO NOT MODIFY THIS CODE  | ////////////////
  ///////////////// v //////////////////////// v ////////////////

  /**
   * Computes the greatest common divisor (GCD) of two numbers.
   * @param {BigInt} a - The first number.
   * @param {BigInt} b - The second number.
   * @returns {BigInt} - The GCD of a and b.
   */
  gcd(a, b) {
    if (b == 0) {
      return a;
    } else {
      return this.gcd(b, a % b);
    }
  }

  /**
   * Computes the least common multiple (LCM) of two numbers.
   * @param {BigInt} a - The first number.
   * @param {BigInt} b - The second number.
   * @returns {BigInt} - The LCM of a and b.
   */
  lcm(a, b) {
    return (a * b) / this.gcd(a, b);
  }

  /**
   * modExp - Performs modular exponentiation: (a^b) % p
   * Computes large powers of a number 'a' raised to 'b' modulo 'p' efficiently.
   *
   * @param {BigInt} a - The base number.
   * @param {BigInt} b - The exponent to which the base is raised.
   * @param {BigInt} p - The modulus.
   * @returns {BigInt} - The result of (a^b) % p.
   */
  modExp(a, b, p) {
    let res = 1n;
    a = a % p;
    while (b > 0) {
      if (b % 2n === 1n) {
        res = (res * a) % p;
      }
      b = b / 2n;
      a = (a * a) % p;
    }
    return res;
  }

  /**
   * Computes the modular inverse of x modulo p using the Extended Euclidean Algorithm.
   * This finds a value y such that (x * y) % p == 1.
   * @param {BigInt} x - The number to find an inverse for.
   * @param {BigInt} p - The modulus.
   * @returns {BigInt} - The modular inverse of x modulo p.
   */
  invMod(x, p) {
    let [a, b] = [1n, 0n];
    let [origP, y] = [p, x];

    while (y > 1n) {
      let q = y / p;
      [y, p] = [p, y % p];
      [a, b] = [b, a - q * b];
    }

    return a < 0n ? a + origP : a;
  }

  /**
   * Generates a random scalar value in the range [1, max_).
   * @param {number} max_ - The upper bound for the random scalar.
   * @returns {number} - A random scalar value less than max_.
   */
  random(max_) {
    max_ = BigInt(max_);
    if (max_ < 1n) {
      throw new Error("max_ must be greater than 0");
    }

    var byteLength = (max_.toString(2).length + 7) >> 3;

    var randomBigInt;

    while (true) {
      randomBigInt = BigInt(
        "0x" + crypto.randomBytes(byteLength).toString("hex")
      );
      if (randomBigInt >= 1n && randomBigInt < max_) {
        return randomBigInt;
      }
    }
  }

  ///////////////// ^ //////////////////////// ^ ////////////////
  ///////////////// | DO NOT MODIFY THIS CODE  | ////////////////
  ///////////////////////////////////////////////////////////////

  /**
   * Generates public and private keys for Paillier encryption.
   * @param {BigInt} p - A large prime number.
   * @param {BigInt} q - A large prime number, distinct from p.
   * @returns {Object} - An object containing the public key {n, g} and private key {λ, μ}.
   */
  generateRandomKeys(p, q) {
    var publicKey, privateKey;
    return { publicKey, privateKey };
  }

  /**
   * Encrypts a message using Paillier encryption.
   * @param {Object} publicKey - The public key containing modulus n and generator g: {n, g}.
   * @param {BigInt} m - The message to encrypt, must be in the range [0, n).
   * @returns {BigInt} - The ciphertext resulting from the encryption.
   */
  encryptMessage(publicKey, m) {
    // return c;
  }

  /**
   * Decrypts a ciphertext using Paillier decryption.
   * @param {Object} privateKey - The private key containing λ and μ.
   * @param {Object} publicKey - The public key containing modulus n.
   * @param {BigInt} c - The ciphertext to decrypt.
   * @returns {BigInt} - The decrypted plaintext message.
   */
  decryptCipherText(privateKey, publicKey, c) {
    // return m;
  }
}

module.exports = { Paillier };
