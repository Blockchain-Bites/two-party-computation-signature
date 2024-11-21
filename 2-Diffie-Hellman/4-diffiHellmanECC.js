// https://github.com/Blockchain-Bites/two-party-computation-signature
// File: 2-Diffie-Hellman/4-diffiHellmanECC.js
// Test: $ node 2-Diffie-Hellman/5-testDiffiHellmanECC.js

var { ECC, Point } = require("../0-EllipticCurve/EllipticCurve");

class DiffieHellman extends ECC {
  /**
   * Constructs an elliptic curve object with curve parameters.
   * @param {number} a - The parameter 'a' in the Weierstrass equation: y^2 = x^3 + ax + b.
   * @param {number} b - The parameter 'b' in the Weierstrass equation.
   * @param {number} p - The prime modulus (finite field size).
   * @param {Point} G - The generator point of the curve.
   * @param {number} q - The order of the elliptic curve (number of points in the group).
   */
  constructor(a, b, p, G, q) {
    super(a, b, p, G, q);
    /** All this properties are accessible through this.a, this.b, ... */
  }

  /**
   * Verifies if two points are equal.
   *
   * @param {Point} P1 - The first point.
   * @param {Point} P2 - The second point.
   * @returns {boolean} - True if the points are equal, false otherwise.
   */
  verify(P1, P2) {
    return false;
  }
}

module.exports = { DiffieHellman, Point };
