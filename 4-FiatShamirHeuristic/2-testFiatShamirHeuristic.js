var { FiatShamirHeuristic, Point } = require("./1-FiatShamirHeuristic");

var q = 11n; // Order of the curve
var a = -2n; // Coefficient 'a' in Weierstrass equation
var b = 7n; // Coefficient 'b' in Weierstrass equation
var p = 17n; // Field size
var G = new Point(9n, 15n);

var fiatShamir = new FiatShamirHeuristic(a, b, p, G, q);

// Step 1: Set up parameters (Alice's public key calculation)
var x = fiatShamir.random(q); // Alice's secret key
var y = fiatShamir.scalarMultiplication(G, x); // public key calculation - Point

// Step 2: Commit Phase (Alice computes t)
var r = fiatShamir.random(q); // Alice's random number
var t = fiatShamir.commit(r); // Point t = r * G (mod p)

// Step 3: Challenge Phase (Alice computes c)
var c = fiatShamir.challenge(G, t);

// Step 4: Response Phase (Alice calculates s)
var s = fiatShamir.calculateS(r, c, x); // s = (r + c * x) mod q
if (s == 0) throw new Error("s = 0. Recompute");

// Step 5: Verification Phase (Anyone verifies the proof)
var valid = fiatShamir.verify(s, t, y, c); // s * G = t + c * y
console.log("Proof is valid:", valid);
