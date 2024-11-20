var { SchnorrECC, Point } = require("./3-schnorrECC");

// Keep the following values
var q = 11n; // Order curve: amount of points on the curve
var a = -2n; // Value 'a' in Weierstrass equation
var b = 7n; // Value 'b' in Weierstrass equation
var p = 17n; // Finite Field or modulus

var G = new Point(9n, 15n); // Generator Point
var schnorrECC = new SchnorrECC(a, b, p, G, q);

// Step 1: Set up parameters (Alice's public key calculation)
var x; // Alice's secret key: use random(q)
var y; // x * G public key calculation - Point

// Step 2: Commit Phase (Alice computes t)
var r; // Alice's random number: use random(q)
var t; // Calculate commit t = r * G (mod p)

// Step 3: Challenge Phase (Bob chooses c)
var c; // Bob's challenge is randomly selected: use random(q)

// Step 4: Response Phase (Alice calculates s)
var s; // Calculate response s = (r - c * x) mod q
if (s == 0) throw new Error("Invalid s = 0, regenerate nonces");

// Step 5: Verification Phase (Bob verifies the response)
var isVerified; // Verify with verify(s, t, y, c);
console.log("Is the response verified?", isVerified);
