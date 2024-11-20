var crypto = require("crypto");
var { PartyOne, PartyTwo, Point } = require("./1-NonInteractiveCommittedZK");

var q = 11n; // Order of the curve
var a = -2n; // Coefficient 'a' in Weierstrass equation
var b = 7n; // Coefficient 'b' in Weierstrass equation
var p = 17n; // Field size

var G = new Point(9n, 15n);
var partyOne = new PartyOne(a, b, p, G, q); // Alice
var partyTwo = new PartyTwo(a, b, p, G, q); // Bob
var sid = crypto.randomUUID(); // different per commitment scheme

// 0 - Alice has already her secret key and public key (ECC)
var x = partyOne.random(partyOne.q); // Alice's secret key
var y = partyOne.scalarMultiplication(partyOne.G, x); // Alice's Public Key - ECC Point

// 1 - Alice executes until response phase and generates, generates proof and creates commitment
var commitment = partyOne.commitProve(sid, x, y);

// 2 - Alices sends the commitment to bob for later validation
partyTwo.savesCommitment(sid, commitment);

// Many other operations happen in between
// Maybe Alice want to change her mind
// However, it is not possible because she must send the same values
// she used for creating the commitment

// 3 - Alice retrieves proof
var { proof } = partyOne.retrieveProof(sid);
var { t, s, c } = proof;

// 4 - Alice decommits by sending its public inputs
var valid = partyTwo.decommitProof(sid, s, t, y, c);
console.log("Validation should be true:", valid);

t = "smt else";
var valid = partyTwo.decommitProof(sid, s, t, y, c);
console.log("Validation should be false:", valid);
