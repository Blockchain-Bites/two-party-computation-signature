const { PaillierHomomorphism } = require("./3-paillierAddHomomorphism");

/** ADDITIVE HOMOMORPHISM*/
/** 1. The system generates Paillier public and private keys*/
var p = 281062564983417584197879099904493071909n;
var q = 266887658682941094264835878405310435687n;
var paillierH = new PaillierHomomorphism();
var { publicKey, privateKey } = paillierH.generateRandomKeys(p, q);

/** 2. People encrypt their blood type*/
var people = [
  { id: "A", m: 0n },
  { id: "B", m: 1n },
  { id: "C", m: 2n },
  { id: "D", m: 3n },
  { id: "E", m: 0n },
  { id: "F", m: 1n },
].map(({ id, m }) => ({ id, c: paillierH.encryptMessage(publicKey, m) }));

/** 3. System returns compatible people*/
var compatiblePeople = paillierH.validateCompatibility(
  privateKey,
  publicKey,
  people
);

/** 4. Checks if it is correct answer*/
if (compatiblePeople.join(" ") == "A-D B-C C-F D-E") {
  console.log("Paillier additive homomorphism is correct");
} else {
  console.log("Paillier additive homomorphism is incorrect");
}
