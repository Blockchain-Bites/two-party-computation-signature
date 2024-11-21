// https://github.com/Blockchain-Bites/two-party-computation-signature
// File: 2-Diffie-Hellman/4-diffiHellmanECC.js
// Test: $ node 2-Diffie-Hellman/5-testDiffiHellmanECC.js

const { DiffieHellman, Point } = require("./4-diffiHellmanECC");

/***********************************/
/** EC DIFFIE-HELLMAN KEY EXCHANGE */
/***********************************/

/** 1. Public Agreement: choosing a, b, p and G*/
var q = 11n; // Order curve: amount of points on the curve
var a = -2n; // Value 'a' in Weierstrass equation
var b = 7n; // Value 'b' in Weierstrass equation
var p = 17n; // Finite Field or modulus

var G = new Point(9n, 15n); // Generator Point
var ec = new DiffieHellman(a, b, p, G, q);

/** 2. Secret Key Generation */
var s_a; // 's_a' is a random scalar value: 0 < s_a < q
var A; // A = s_a • G (mod p)

var s_b; // 's_b' is a random scalar value: 0 < s_b < q
var B; // B = s_b • G (mod p)

/** 3. Shared secret computation */
var secretA; // s_a • B (mod p)
var secretB; // s_b • A (mod p)

var isSameSecret = ec.verify(secretA, secretB); // Check if both secrets are the same
console.log("Shared secret is the same: ", isSameSecret);
