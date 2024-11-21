// https://github.com/Blockchain-Bites/two-party-computation-signature
// File: 1-SchnorrPoK/3-schnorrECC.js
// Test: $ node 1-SchnorrPoK/4-testSchnorrECC.js

var { ECC, Point } = require("../0-EllipticCurve/EllipticCurve");

class SchnorrECC extends ECC {
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
   * Step 2: Commit phase. Alice (the prover) generates a commitment t based on a random value r.
   * t = r * G (mod p), where G is the generator point. Scalar Multiplication.
   * @param {number} r - Random scalar selected by the prover.
   * @returns {Point} - The commitment point t.
   */
  commit(r) {
    var t; // t = r * G
    return t;
  }

  /**
   * Step 4: Response phase. Alice (the prover) calculates the response s.
   * s = (r - c * x) mod q.
   * @param {number} r - The random value used in the commitment phase.
   * @param {number} c - The challenge value provided by the verifier.
   * @param {number} x - The prover's secret (private key).
   * @returns {number} - The response value s.
   */
  calculateS(r, c, x) {
    var s; // Compute s = (r - c * x) mod q
    // if s < 0n then s += q. Ensure s is non-negative
    return s;
  }

  /**
   * Step 5: Verification phase. Bob (the verifier) checks if the equation t = s*G + c*y holds.
   * @param {number} s - The response from the prover.
   * @param {Point} t - The commitment point from the commit phase.
   * @param {Point} y - The prover's public key (y = x * G).
   * @param {number} c - The challenge value from the verifier.
   * @returns {boolean} - True if the proof is valid, false otherwise.
   */
  verify(s, t, y, c) {
    var rightSide; // s*G + c*y
    var leftSide = t; // t is the commitment

    // Check if leftSide == rightSide (both x and y coordinates must match)
    // if (leftSide.x === rightSide.x && leftSide.y === rightSide.y) {
    //   return true;
    // }

    return false;
  }
}

module.exports = { SchnorrECC, Point };
