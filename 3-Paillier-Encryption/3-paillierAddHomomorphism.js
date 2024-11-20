const { Paillier } = require("./1-paillierEncryption");

class PaillierHomomorphism extends Paillier {
  /**
   * Adds two encrypted values homomorphically, resulting in the encryption of their sum.
   *
   * @param {BigInt} c1 - The first ciphertext
   * @param {BigInt} c2 - The second ciphertext
   * @param {Object} publicKey - The Paillier public key
   * @returns {BigInt} - The encrypted result of c1 + c2
   */
  addCipherTexts(c1, c2, publicKey) {}

  /**
   * Validates compatibility between pairs of encrypted values by summing each pair
   * and checking if the decrypted sum matches the target compatibility value (3).
   *
   * @param {Object} privateKey - The private key used in Paillier decryption.
   * @param {Object} publicKey - The public key used in Paillier encryption.
   * @param {Array} list - Object list: each object {id, c}.
   * @returns {Array<string>} - An array of strings, each representing a compatible pair (formatted as "id1-id2").
   */
  validateCompatibility(privateKey, publicKey, list) {
    var compatiblePeople = [];
    // Complete here...
    return compatiblePeople;
  }
}

module.exports = { PaillierHomomorphism };
