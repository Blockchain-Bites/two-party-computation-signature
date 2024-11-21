const { DiffieHellman } = require("./1-diffiHellman");

var dh = new DiffieHellman();
var g, p;

/********************************/
/*** CHECKING PRIMITIVE ROOT  ***/
/********************************/

g = 2n;
p = 7n;
console.log(`${g} should be false`, dh.isPrimitiveRoot(g, p));

g = 3n;
p = 7n;
console.log(`${g} should be true`, dh.isPrimitiveRoot(g, p));

g = 2n;
p = 41n;
console.log(`${g} should be false`, dh.isPrimitiveRoot(g, p));

g = 6n;
p = 41n;
console.log(`${g} should be true`, dh.isPrimitiveRoot(g, p));
