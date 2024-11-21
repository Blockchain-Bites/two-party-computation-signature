// https://github.com/Blockchain-Bites/two-party-computation-signature
// File: 2-Diffie-Hellman/3-testDiffiHellman.js
// Test: $ node 2-Diffie-Hellman/3-testDiffiHellman.js

const { DiffieHellman } = require("./1-diffiHellman");

var dh = new DiffieHellman();
var g, p;

/********************************/
/** DIFFIE-HELLMAN KEY EXCHANGE */
/********************************/

/** 1. Public Agreement: choosing g and p */
p = 1066340417491710595814572169n;
g; // Find an appropriate primitive root!
if (!dh.isPrimitiveRoot(g, p)) throw Error("g must be a primitive root!");

/** 2. Secret Key Generation */
var a; // 'a' is a random secret value: 0 < a < p
var A; // A = g^a (mod p)

var b; // 'b' is a random secret value: 0 < b < p
var B; // B = g^b (mod p)

/** 3. Shared Secret Computation */
var secretA; // B^a (mod p)
var secretB; // A^b (mod p)

console.log(
  "Alice and Bob have the same secret key:",
  !!secretA && secretA === secretB
);
