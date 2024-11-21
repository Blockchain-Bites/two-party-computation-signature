// https://github.com/Blockchain-Bites/two-party-computation-signature
// File: 2-Diffie-Hellman/1-diffiHellman.js
// Test: $ node 2-Diffie-Hellman/2-testDHPrimitiveRoot.js

var crypto = require("crypto");

class DiffieHellman {
  ///////////////////////////////////////////////////////////////
  ///////////////// | DO NOT MODIFY THIS CODE  | ////////////////
  ///////////////// v //////////////////////// v ////////////////

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
   * _calculatePrimeFactors - Calculates the prime factors of a number 'n'.
   *
   * @param {BigInt} n - The number to factorize.
   * @returns {Array<Object>} - An array of objects where each object is { factor: BigInt, exp: BigInt }.
   */
  _calculatePrimeFactors(n) {
    let factors = [];
    let expCounter = 0n;
    while (n % 2n === 0n) {
      n = n / 2n;
      expCounter += 1n;
    }
    if (expCounter > 0) {
      factors.push({ factor: 2n, exp: expCounter });
    }

    for (let i = 3n; i <= this._sqrtRoot(n); i += 2n) {
      expCounter = 0n;
      while (n % i === 0n) {
        n = n / i;
        expCounter += 1n;
      }
      if (expCounter > 0) {
        factors.push({ factor: i, exp: expCounter });
      }
    }

    if (n > 2n) {
      factors.push({ factor: n, exp: 1n });
    }

    return factors;
  }

  /**
   * _sqrtRoot - Computes the integer square root of a given BigInt 'n'
   * This method uses Newton's method
   *
   * @param {BigInt} n - The number for which the square root is to be computed
   * @returns {BigInt} - The integer square root of n
   */
  _sqrtRoot(n) {
    if (n < 0n) throw new Error("Negative square root is not supported");
    if (n === 0n || n === 1n) return n;

    let x = n;
    let y = 1n;
    while (x > y) {
      x = (x + y) / 2n;
      y = n / x;
    }
    return x;
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
   * isPrimitiveRoot - Checks if 'g' is a primitive root modulo 'p'.
   *
   * @param {BigInt} g - The potential primitive root
   * @param {BigInt} p - The prime modulus
   * @returns {Boolean} - True if 'g' is a primitive root modulo 'p', false otherwise.
   */
  isPrimitiveRoot(g, p) {
    return true;
  }
}

module.exports = { DiffieHellman };
