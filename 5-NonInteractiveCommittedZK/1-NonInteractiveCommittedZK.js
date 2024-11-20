var {
  FiatShamirHeuristic,
  Point,
} = require("../4-FiatShamirHeuristic/1-FiatShamirHeuristic");

class PartyOne extends FiatShamirHeuristic {
  constructor(a, b, p, G, q) {
    super(a, b, p, G, q);
    this.store = {};
  }

  generateProof(x, y) {
    var r; // Alice's random number (should be kept secret)
    var t; // Point t = r * G (mod p)
    var c; // Alice's challenge in Fiat-Shamir Heuristic (hash function)
    var s; // s = (r + c * x) mod q
    if (s == 0) throw new Error("s is 0. Recompute.");
    var proof = { t, s, c, y }; // all public values
    return proof;
  }

  // 1 - Alice executes until response phase and generates, generates proof and creates commitment
  commitProve(sid, x, y) {
    var proof; // generateProof
    var commitment; // hash(t, s)
    this.store[sid] = { commitment, proof };
    return commitment;
  }

  // 3 - Alice retrieves proof
  retrieveProof(sid) {
    return this.store[sid];
  }
}

class PartyTwo extends FiatShamirHeuristic {
  constructor(a, b, p, G, q) {
    super(a, b, p, G, q);
    this.store = {};
  }

  // 2 - Bob saves the commitment for later validation
  savesCommitment(sid, commitment) {
    this.store[sid] = commitment;
  }

  // 4 - Alice decommits by sending its public inputs
  decommitProof(sid, s, t, y, c) {
    var commitment = this.store[sid];
    if (!commitment) throw new Error("No commitment found for sid.");

    // Recompute the commitment
    // if hash(t, s) != commitment then return false, true otherwise

    // verify that s · G = t + c · y. Use verify from FiatShamirHeuristic
    return false;
  }
}

module.exports = { PartyOne, PartyTwo, Point };
