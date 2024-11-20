const { Schnorr } = require("./1-schnorr");

// Testing Schnorr class
// Step 1: Set up parameters (Alice's public key calculation)
var g = 3; // g is a generator
var n = 7; // n is the field size
var q = 6; // q is the order of the group

const schnorr = new Schnorr(g, n, q);
var x; // Alice's secret key x = 5
var y; // schnorr.modExp(...); // public key calculation

// Step 2: Commit Phase (Alice computes t)
var r; // Alice's random number, here r = 3
var t;

// Step 3: Challenge Phase (Bob chooses c)
var c; // Bob's challenge is randomly selected, here c = 4

// Step 4: Response Phase (Alice calculates s)
var s; // schnorr.calculateS(...);

// Step 5: Verification Phase (Bob verifies the response)
var isVerified; // schnorr.verify(...);
console.log("Is the response verified?", isVerified);
