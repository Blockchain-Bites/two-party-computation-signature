var crypto = require("crypto");

// Do not modify this class
class Point {
  /**
   * Constructs a point on the elliptic curve.
   * @param {number} x - The x-coordinate of the point.
   * @param {number} y - The y-coordinate of the point.
   */
  constructor(x, y) {
    this.x = BigInt(x);
    this.y = BigInt(y);
  }
}

class ECC {
  /**
   * Constructs an elliptic curve object with curve parameters.
   * @param {number} a - The parameter 'a' in the Weierstrass equation: y^2 = x^3 + ax + b.
   * @param {number} b - The parameter 'b' in the Weierstrass equation.
   * @param {number} p - The prime modulus (finite field size).
   * @param {Point} G - The generator point of the curve.
   * @param {number} q - The order of the elliptic curve (number of points in the group).
   */
  constructor(a, b, p, G, q) {
    this.a = BigInt(a);
    this.b = BigInt(b);
    this.p = BigInt(p);
    this.q = BigInt(q);
    this.G = G;
  }

  /**
   * Checks whether a point P lies on the elliptic curve defined by y^2 = x^3 + ax + b (mod p).
   * @param {Point} P - The point to be checked.
   * @returns {boolean} - True if the point lies on the curve, false otherwise.
   */
  isPoint(P) {
    var { x, y } = P;
    if (x < 0n || x >= this.p || y < 0n || y >= this.p) {
      return false; // Check if coordinates are within the valid range
    }

    // Check the curve equation: y^2 == x^3 + ax + b (mod p)
    let leftSide = this.sqr(y) % this.p;
    let rightSide = (this.sqr(x) * x + this.a * x + this.b) % this.p;

    if (rightSide < 0) rightSide += this.p;
    if (leftSide < 0) leftSide += this.p;

    return leftSide === rightSide;
  }

  /**
   * Calculates the modular inverse of x mod p using brute-force method.
   * Finds y such that (x * y) % p = 1.
   * @param {number} x - The number for which the inverse is to be calculated.
   * @param {number} p - The modulus value.
   * @returns {number} - The modular inverse of x mod p.
   */
  invMod(x, p) {
    x = BigInt(x);
    p = BigInt(p);

    var i;

    if (x < 0n) x += p;

    for (i = 0n; i < p; i++) {
      if ((x * i) % p == 1n) return i;
    }
    throw Error("No multiplicative inverse found");
  }

  /**
   * Performs division modulo p: (x / y) mod p is calculated as (x * invMod(y, p)) % p.
   * @param {number} x - The numerator.
   * @param {number} y - The denominator (mod p).
   * @returns {number} - The result of (x / y) mod p.
   */
  divMod(x, y) {
    return (x * this.invMod(y, this.p)) % this.p;
  }

  /**
   * Squares a number modulo p: (x^2) % p.
   * @param {number} x - The number to be squared.
   * @returns {number} - The result of (x^2) % p.
   */
  sqr(x) {
    return (x * x) % this.p;
  }

  /**
   * Doubles a point on the elliptic curve: Computes 2 * A.
   * @param {Point} A - The point to be doubled.
   * @returns {Point} - The resulting point after doubling.
   */
  pointDouble(A) {
    return this.pointAddition(A, A);
  }

  /**
   * Adds two points on the elliptic curve: A + B.
   * @param {Point} A - First point.
   * @param {Point} B - Second point.
   * @returns {Point} - The resulting point after addition.
   */
  pointAddition(A, B) {
    // A = (x1, y1)
    // B = (x2, y2)
    if (A.x == 0n && A.y == 0n) {
      return new Point(B.x, B.y);
    } else if (B.x == 0n && B.y == 0n) {
      return new Point(A.x, A.y);
    } else if (A.x == B.x && A.y == -B.y) {
      return new Point(0, 0);
    } else if (A.x == B.x && A.y != B.y) {
      return new Point(0, 0);
    } else {
      let l, x3, y3;
      // P != Q
      if (A.x != B.x || A.y != B.y) {
        l = this.divMod(B.y - A.y, B.x - A.x);
      } else if (A.x == B.x && A.y == B.y) {
        // P == Q
        l = this.divMod(3n * this.sqr(A.x) + this.a, 2n * A.y);
      } else {
        new Error("No scenario here");
      }
      x3 = (l * l - A.x - B.x) % this.p;
      y3 = (l * (A.x - x3) - A.y) % this.p;
      if (x3 < 0n) x3 += this.p;
      if (y3 < 0n) y3 += this.p;
      return new Point(x3, y3);
    }
  }

  /**
   * Performs scalar multiplication: Computes num * P (mod p) using double-and-add method.
   * @param {Point} P - The point to be multiplied.
   * @param {number} num - The scalar value for multiplication.
   * @returns {Point} - The resulting point after scalar multiplication.
   */
  scalarMultiplication(P, num) {
    // P = (x1, y1)
    let Q = P;
    let R = new Point(0, 0);
    while (num > 0n) {
      if (num % 2n == 1n) R = this.pointAddition(R, Q);
      Q = this.pointDouble(Q);
      num = num / 2n;
      if (num == 0n) break;
    }
    if (R.x < 0n) R.x += this.p;
    if (R.y < 0n) R.y += this.p;

    if (!this.isPoint(R)) {
      throw new Error("Not a point on the Elliptic Curve");
    }

    return R;
  }

  generateKeyPair(q) {
    q = BigInt(q);

    if (q <= 1n) throw new Error("Value must be greater than 1.");

    const privateKey = this.random(q - 2n) + 1n;
    const publicKey = this.scalarMultiplication(this.G, privateKey);

    return { privateKey, publicKey };
  }

  gcd(a, b) {
    return b === 0n ? a : this.gcd(b, a % b);
  }

  lcm(a, b) {
    return (a * b) / this.gcd(a, b);
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
}

module.exports = { ECC, Point };
