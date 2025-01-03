var crypto = require("crypto");

var {
  ECC,
  Point,
  combineInstancesInto,
} = require("../0-EllipticCurve/EllipticCurve");
var {
  Paillier,
} = require("../3-Paillier-Encryption/1-paillierEncryption");

// Elliptic curve parameters
const q = 10133n; // Order of the curve (number of points)
const a = 9158n; // Coefficient 'a' in the Weierstrass equation
const b = 7614n; // Coefficient 'b' in the Weierstrass equation
const G = new Point(3779n, 1910n); // Generator point
const p = 9967n; // Prime modulus (field size)

// Initialize cryptographic classes
const ecc = new ECC(a, b, p, G, q);
const paillier = new Paillier();

class WalletP1 {
  constructor(...instances) {
    /** With 'combineInstancesInto' you can access all instances properties with 'this.property'*/
    combineInstancesInto(this, instances);
    this.storage = {};
  }

  /**
   * Computes a hash value based on the provided inputs.
   * @param {...any} inputs - A variable number of inputs to be hashed. Each input can be a number, string, or elliptic curve point.
   * @returns {BigInt} - The resulting hash as a BigInt.
   */
  hash(...inputs) {
    const data = inputs.map((input) => input?.toString()).join("|");
    return BigInt(
      "0x" + crypto.createHash("sha256").update(data).digest("hex")
    );
  }

  P1FirstMessage(sessionId) {
    // Step 1(a): Choose a random scalar x1 in the range [q/3, 2q/3]. Compute Q1 = x1 * G
    const lowerBound = this.q / 3n;
    const upperBound = (2n * this.q) / 3n;
    const x1 = lowerBound + this.random(upperBound - lowerBound);
    const Q1 = this.scalarMultiplication(this.G, x1);

    // 2. P1 sends the commitment (t, s) and a proof of knowledge F^{RDL}_{com-zk} of its discrete log to P2.
    // 2.1 Schnorr Proof: Commitment Phase
    const r = this.random(this.q); // Random nonce r
    const t = this.scalarMultiplication(this.G, r); // Compute t = r * G
    // 2.2 Schnorr Proof: Challenge Phase (Fiat-Shamir Heuristic)
    const c = this.hash(this.G, Q1, t); // Compute challenge c = Hash(G || Q1 || t)
    // 2.3 Schnorr Proof: Response Phase
    const s = (r + c * x1) % this.q; // Compute response s = r + c * x1 (mod q)
    if (s == 0n) throw new Error("s is 0. Recalculate.");
    // 2.4 Commitment Hash: Commit to the Schnorr proof elements (t, s)
    const commitmentFRDLcomZK = this.hash(t, s); // Compute commitment C = Hash(t || s)
    // 2.5 Store for own record in the key generation subprotocol
    this.storage[sessionId] = {
      keyGeneration: { x1, Q1, r, t, s, c, commitmentFRDLcomZK },
    };
    // 2.6 Return commitment for sending it to P2
    return { commitmentFRDLcomZK };
  }

  // P1 is saving the FRDLzk proof from p2 from Step 2(c)
  receiveFRDLzkProofKeyG(sessionId, FRDLzkProof) {
    this.storage[sessionId] = {
      keyGeneration: {
        ...FRDLzkProof,
        ...this.storage[sessionId].keyGeneration,
      },
    };
  }

  P1SecondMessage(sessionId, securityParameter) {
    const { t2, s2, c2, Q2 } = this.storage[sessionId].keyGeneration;
    if (!t2 || !s2 || !c2 || !Q2) {
      throw new Error("No proof has been received from P2.");
    }

    // Step 3(a): P1 receives proof FRDLzk from P2. If not, aborts.
    // Recompute the left and right sides of the Schnorr verification equation
    const leftSide = this.scalarMultiplication(this.G, s2);
    const rightSide = this.pointAddition(t2, this.scalarMultiplication(Q2, c2));

    if (leftSide.x !== rightSide.x || leftSide.y !== rightSide.y) {
      throw new Error("Schnorr proof FRDLzk verification failed for Q2.");
    }

    // Step 3(b): P1 sends decommitment proof FRDLcomzk to P2.
    const { t, s, Q1, c } = this.storage[sessionId].keyGeneration;
    const decommitmentMessage = { sessionId, t, s, Q1, c };

    // Step 3(c): Generate a Paillier key pair of length (N) max(3 * log2(|q|) + 1, security param) and and encrypt x1
    // Generate Paillier keys
    const paillier_p = 281062564983417584197879099904493071909n;
    const paillier_q = 266887658682941094264835878405310435687n;

    const { publicKey: pkPaillierP1, privateKey: skPaillierP1 } =
      this.generateRandomKeys(paillier_p, paillier_q);

    const N = pkPaillierP1.n; // Modulus of the Paillier public key

    // Calculate the minimum required length: max(3 * log2(|q|) + 1, securityParameter)
    const log2Q = BigInt(this.q.toString(2).length); // Bit length of q
    const requiredLength = BigInt(3) * log2Q + 1n;
    const minLength =
      requiredLength > securityParameter ? requiredLength : securityParameter;

    // Validate the length of N
    const lengthOfN = BigInt(N.toString(2).length);
    if (lengthOfN < minLength) {
      throw new Error(
        `Invalid Paillier key length: ${lengthOfN} bits. It must be at least ${minLength} bits.`
      );
    }

    // Encrypt x1 using Paillier encryption
    const { x1 } = this.storage[sessionId].keyGeneration;
    const c_key = this.encryptMessage(pkPaillierP1, x1);

    this.storage[sessionId] = {
      keyGeneration: {
        pkPaillierP1,
        skPaillierP1,
        c_key,
        paillier_p,
        paillier_q,
        ...this.storage[sessionId].keyGeneration,
      },
    };

    // Step 3(d): P1 sends the Paillier public key and the encrypted x1 to P2
    return { sessionId, pkPaillierP1, c_key, decommitmentMessage };
  }

  // Step 4: ZK Proofs (Using Session ID)
  P1ZeroKnowledgeProofs(sessionId) {
    // i. Proving L_P
    const { pkPaillierP1, c_key, paillier_p, paillier_q } =
      this.storage[sessionId].keyGeneration;
    const N = pkPaillierP1.n;
    const lambda = this.lcm(paillier_p - 1n, paillier_q - 1n);

    // Generate a zero-knowledge proof for LP
    const gcdCheck = this.gcd(N, lambda);
    if (gcdCheck !== 1n) {
      throw new Error("Invalid Paillier public key: N does not belong to L_P.");
    }

    // ii. Proving L_{PDL}
    const { Q1, x1 } = this.storage[sessionId].keyGeneration;
    // Schnorr-like ZK proof for (c_key, pk, Q1) ∈ L_{PDL}
    // Schnorr Proof: Commitment Phase
    const r = this.random(this.q); // Random nonce for the proof
    const t = this.scalarMultiplication(this.G, r); // Compute t = r * G
    // Fiat-Shamir Heuristic for Challenge
    // c reveals the connection between the encryption of x1 (c_key) and Q1
    const c = this.hash(c_key, pkPaillierP1.n, Q1, t) % this.q; // Compute challenge c = Hash(c_key || N || Q1 || t)
    if (c == 0n) throw new Error("c is 0. Recalculate.");

    // Response Phase
    const s = (r + c * x1) % this.q; // Compute response s = r + c * x1 (mod q)

    // Store ZK proof data for this session
    // this.storage[sessionId].ZKProof = { t, s, c };

    // Return ZK proof data for P2 to verify
    const zkProof = {
      sessionId,
      lpProof: { N, valid: gcdCheck === 1n }, // Proof for L_P
      lpdProof: { t, s, c }, // Proof for L_{PDL}
    };

    return zkProof;
  }

  // Step 6: Compute the final shared public key Q
  computeSharedPublicKey(sessionId) {
    const Q2 = this.storage[sessionId].keyGeneration.Q2;
    const x1 = this.storage[sessionId].keyGeneration.x1;
    const Q = this.scalarMultiplication(Q2, x1);
    this.storage[sessionId].keyGeneration.Q = Q;
    return Q;
  }

  /******* SIGNING *******/
  // 1. P1's First Message
  P1SigningFirstMessage(sessionId) {
    // (a) P1 chooses a random k1 and computes R1 = k1 * G.
    const k1 = this.random(this.q);
    const R1 = this.scalarMultiplication(this.G, k1);

    // (b) P1 will send the commitment message FDRLcomZK (t1, s1) to P2
    // Schnorr Proof: Commitment Phase
    const r1 = this.random(this.q);
    const t1 = this.scalarMultiplication(this.G, r1);

    // Schnorr Proof: Challenge Phase
    const c1 = this.hash(this.G, R1, t1) % this.q;
    if (c1 == 0n) throw new Error("c1 is 0. Recalculate.");

    // Schnorr Proof: Response Phase
    const s1 = (r1 + c1 * k1) % this.q;
    if (s1 == 0n) throw new Error("s1 is 0. Recalculate.");

    // Commitment Hash: Commit to the Schnorr proof elements (t1, s1)
    const signingCommitment = this.hash(t1, s1);

    // Store session-specific values under the session ID for decommitment later
    this.storage[sessionId] = {
      ...this.storage[sessionId],
      signing: { R1, t1, s1, k1, signingCommitment, c1 },
    };

    return { signingCommitment };
  }

  // Wallet P1 receives the proof
  receiveSigningProof(sessionId, signingProofFRDLzk) {
    this.storage[sessionId].signing = {
      ...signingProofFRDLzk,
      ...this.storage[sessionId].signing,
    };
  }

  // 3. P1's Second Message
  P1SigningSecondMessage(sessionId) {
    // (a) P1 receives proof FRDLzk from P2. This is the time when P1 verifies if P2's proof FRDLzk checks.
    const { t2, s2, c2, R2 } = this.storage[sessionId].signing;
    const leftSide = this.scalarMultiplication(this.G, s2);
    const rightSide = this.pointAddition(t2, this.scalarMultiplication(R2, c2));

    if (leftSide.x !== rightSide.x || leftSide.y !== rightSide.y) {
      throw new Error("Schnorr proof verification failed for Q2.");
    }

    // (b) P1 sends decommitment proof FRDLcomZK to P2
    const { signingCommitment, c1, R1, t1, s1 } =
      this.storage[sessionId].signing;

    const decommitmentMessage = {
      sessionId,
      R1,
      t1,
      s1,
      signingCommitment,
      c1,
    };

    return decommitmentMessage;
  }

  // 5. P1 generates output
  P1SigningOutput(sessionId, c3, message) {
    // (a) P1 computes R = k1 · R2. Denote R = (rx,ry). Then, P1 computes r = rx mod q.
    const { k1, R2 } = this.storage[sessionId].signing;
    const R = this.scalarMultiplication(R2, k1);
    const r = R.x % this.q;

    // (b) P1 computes s′ = Dec(c3) and s′′ = k1^−1 · s′ mod q. P1 sets s = min(s′′ , q − s′′)
    const { pkPaillierP1, skPaillierP1 } =
      this.storage[sessionId].keyGeneration;

    const sPrime = this.decryptCipherText(skPaillierP1, pkPaillierP1, c3);

    var invk1 = this.invMod(k1, this.q);
    const sPrimePrime = (invk1 * sPrime) % this.q;
    const s =
      sPrimePrime < this.q - sPrimePrime ? sPrimePrime : this.q - sPrimePrime;
    if (s > (this.q - 1n) / 2n)
      throw new Error("s must be lower than (q - 1)/2");
    const signature = { r, s };

    // (c) P1 verifies that (r, s) is a valid signature with public key Q. If yes it outputs the signature (r, s); otherwise, it aborts.
    const { Q } = this.storage[sessionId].keyGeneration;
    var hash_q_verify = H_q(message, this.q);
    var s_inv = this.invMod(s, this.q);
    var u1 = (hash_q_verify * s_inv) % this.q;
    var u2 = (r * s_inv) % this.q;

    var point = this.pointAddition(
      this.scalarMultiplication(this.G, u1),
      this.scalarMultiplication(Q, u2)
    );
    var v = point.x % this.q;

    if (v !== r) {
      throw new Error("Invalid signature.");
    }

    return signature;
  }
}

class WalletP2 {
  constructor(...instances) {
    /** With 'combineInstancesInto' you can access all instances properties with 'this.property'*/
    combineInstancesInto(this, instances);
    this.storage = {};
  }

  /**
   * Computes a hash value based on the provided inputs.
   * @param {...any} inputs - A variable number of inputs to be hashed. Each input can be a number, string, or elliptic curve point.
   * @returns {BigInt} - The resulting hash as a BigInt.
   */
  hash(...inputs) {
    const data = inputs.map((input) => input?.toString()).join("|");
    return BigInt(
      "0x" + crypto.createHash("sha256").update(data).digest("hex")
    );
  }

  receiveFRDLcomZKCommitmentKeyG(sessionId, commitmentFRDLcomZK) {
    this.storage[sessionId] = {
      keyGeneration: { commitmentFRDLcomZK },
    };
  }

  P2FirstMessage(sessionId) {
    // Step 2(a): Verify the proof-receipt from F^{RDL}_{com-zk} using the session ID
    if (!this.storage[sessionId]?.keyGeneration.commitmentFRDLcomZK) {
      throw new Error("No valid proof-receipt F^{RDL}_{com-zk} found");
    }

    // Step 2(b): P2 chooses a random scalar x2 in the range [0, q-1] and computes Q2 = x2 * G
    const x2 = this.random(this.q);
    const Q2 = this.scalarMultiplication(this.G, x2);
    // Step 2(c): Construct a Schnorr proof for x2 using F^{RDL}_{zk}
    // Schnorr Proof: Commitment Phase
    const r2 = this.random(this.q); // Random nonce for the Schnorr proof
    const t2 = this.scalarMultiplication(this.G, r2); // Compute t2 = r2 * G

    // Schnorr Proof: Challenge Phase (Fiat-Shamir Heuristic)
    const c2 = this.hash(this.G, Q2, t2); // Compute challenge c2 = Hash(G || Q2 || t2)

    // Schnorr Proof: Response Phase
    const s2 = (r2 + c2 * x2) % this.q; // Compute response s2 = r2 + c2 * x2 (mod q)
    if (s2 == 0n) throw new Error("s2 is 0. Recalculate.");

    // Store x2, Q2, t2, s2, and c2 for this session
    this.storage[sessionId] = {
      keyGeneration: {
        x2,
        Q2,
        t2,
        s2,
        c2,
        ...this.storage[sessionId].keyGeneration,
      },
    };

    // Send proof F^{RDL}_{zk} Q2, c2, s2 and t2 to P1
    return { t2, s2, c2, Q2 };
  }

  // P2 will need to store pkPaillierP1, c_key, decommitmentMessage in it
  receiveFRDLcomZKDecommitmentKeyG(
    sessionId,
    decommitmentMessage,
    pkPaillierP1,
    c_key
  ) {
    this.storage[sessionId] = {
      keyGeneration: {
        decommitmentMessage,
        pkPaillierP1,
        c_key,
        ...this.storage[sessionId].keyGeneration,
      },
    };
  }

  // Step 5: P2’s Verification (Using Session ID)
  P2Verification(sessionId, zkProof, securityParameter = 256) {
    // Step 5(a): Verify the decommitment from F^{RDL}_{com-zk}
    const { pkPaillierP1, c_key, decommitmentMessage, commitmentFRDLcomZK } =
      this.storage[sessionId].keyGeneration;
    const { t, s, Q1, c } = decommitmentMessage;

    const leftSideNIZK = this.scalarMultiplication(this.G, s);
    const rightSideNIZK = this.pointAddition(
      t,
      this.scalarMultiplication(Q1, c)
    );
    if (
      leftSideNIZK.x !== rightSideNIZK.x ||
      leftSideNIZK.y !== rightSideNIZK.y
    ) {
      throw new Error("Zero-knowledge proof in F^{RDL}_{zk} failed.");
    }

    // Recompute the commitment hash using t and s
    const recomputedCommitment = this.hash(t, s);
    if (recomputedCommitment !== commitmentFRDLcomZK) {
      throw new Error(
        "Decommitment verification failed: Commitment hash mismatch."
      );
    }

    // Step 5(b): Verify that c_key ∈ Z^*_{N^2}
    const N = pkPaillierP1.n;
    const N2 = N * N;
    if (c_key <= 0n || c_key >= N2 || this.gcd(c_key, N2) !== 1n) {
      throw new Error(
        "Invalid Paillier ciphertext: c_key does not belong to Z^*_{N^2}."
      );
    }

    // Step 5(c): Verify ZK proofs L_P and L_{PDL}
    const { lpProof, lpdProof } = zkProof;
    // Verify N ∈ L_P
    if (!lpProof.valid) {
      throw new Error("Zero-knowledge proof L_P failed.");
    }

    // Verify L_{PDL} using Schnorr-like proof
    const { t: t2, s: s2, c: c2 } = lpdProof;
    if (s2 == 0n) throw new Error("s2 is 0. Recalculate.");

    const leftSide = this.scalarMultiplication(this.G, s2);
    const rightSide = this.pointAddition(t2, this.scalarMultiplication(Q1, c2));
    if (leftSide.x !== rightSide.x || leftSide.y !== rightSide.y) {
      throw new Error("Zero-knowledge proof for L_{PDL} failed.");
    }

    // Step 5(d): Verify the length of the Paillier key pk = N
    const log2Q = BigInt(this.q.toString(2).length); // Bit length of q
    const requiredLength = BigInt(3) * log2Q + 1n;
    const minLength =
      requiredLength > securityParameter ? requiredLength : securityParameter;
    const lengthOfN = BigInt(N.toString(2).length);

    if (lengthOfN < minLength) {
      throw new Error(
        `Invalid Paillier key length: ${lengthOfN} bits. It must be at least ${minLength} bits.`
      );
    }

    return true;
  }

  // Step 6: Compute the final shared public key Q
  computeSharedPublicKey(sessionId) {
    const Q1 = this.storage[sessionId].keyGeneration.decommitmentMessage.Q1;
    const x2 = this.storage[sessionId].keyGeneration.x2;
    const Q = this.scalarMultiplication(Q1, x2);
    this.storage[sessionId].keyGeneration.Q = Q;
    return Q;
  }

  /******* SIGNING *******/
  // Wallet P2 receives the commitment
  receiveSigningCommitment(sessionId, { signingCommitment }) {
    this.storage[sessionId].signing = { signingCommitment };
  }

  P2SigningFirstMessage(sessionId) {
    // (a) **P2** receives proof-receipt FDRLcomZK from **P1**.
    if (!this.storage[sessionId].signing.signingCommitment) {
      throw new Error("No valid proof receipt found");
    }

    // (b) **P2** chooses a random k2 and computes R2 = k2 * G
    const k2 = this.random(this.q);
    const R2 = this.scalarMultiplication(this.G, k2);

    // (c) Schnorr Proof: Commitment Phase
    const r2 = this.random(this.q);
    const t2 = this.scalarMultiplication(this.G, r2);

    // Schnorr Proof: Challenge Phase
    const c2 = this.hash(this.G, R2, t2) % this.q;
    if (c2 == 0n) throw new Error("c2 is 0. Recalculate.");

    // Schnorr Proof: Response Phase
    const s2 = (r2 + c2 * k2) % this.q;
    if (s2 == 0n) throw new Error("s2 is 0. Recalculate.");

    this.storage[sessionId].signing = {
      R2,
      t2,
      s2,
      k2,
      ...this.storage[sessionId].signing,
    };

    // Return proof FRDLzk for P1
    return { t2, s2, c2, R2 };
  }

  // Wallet P2 receives the decommitment message
  receiveSigningDecommitment(sessionId, decommitmentMessage) {
    this.storage[sessionId].signing = {
      ...decommitmentMessage,
      ...this.storage[sessionId].signing,
    };
  }

  // 4. P2's second message
  P2SigningSecondMessage(sessionId, m_prime) {
    // (a) P2 receives decommitment proof FRDLcomZK from P1.
    // If not, aborts. Now P2 will be able to recompute the hash and check the if the Fiat-Shamir Heuristic holds
    const { t1, s1, R1, c1: c1Dec } = this.storage[sessionId].signing;

    const leftSideNIZK = this.scalarMultiplication(this.G, s1);
    const rightSideNIZK = this.pointAddition(
      t1,
      this.scalarMultiplication(R1, c1Dec)
    );
    if (
      leftSideNIZK.x !== rightSideNIZK.x ||
      leftSideNIZK.y !== rightSideNIZK.y
    ) {
      throw new Error("Zero-knowledge proof in F^{RDL}_{zk} failed.");
    }

    // Recompute the commitment hash using t and s
    const { signingCommitment } = this.storage[sessionId].signing;
    const recomputedCommitment = this.hash(t1, s1);
    if (recomputedCommitment !== signingCommitment) {
      throw new Error(
        "Decommitment verification failed: Commitment hash mismatch."
      );
    }

    // (b) P2 computes R = k2 * R1. Denote R = (r_x, r_y). Then P2 computes r = r_x mod q
    const { k2 } = this.storage[sessionId].signing;
    const R = this.scalarMultiplication(R1, k2);
    const r = R.x % this.q;

    // (c) P2 chooses a random ρ in Z_q^2 and random r ̃ ∈ Z^*_N (verifying explicitly that gcd(r ̃, N ) = 1)
    const { c_key, pkPaillierP1, x2 } = this.storage[sessionId].keyGeneration;
    var rho;
    while (!rho || this.gcd(rho, this.q) != 1) {
      rho = this.random(this.q ** 2n);
    }

    var invk2 = this.invMod(k2, this.q);

    // Then, P2 computes c1, v, c2 and c3
    // c1 = Enc[(rho * q + k2^-1 * m_prime) % q]
    // v = k2^{-1} * r * x2 mod q,
    // c2 = c_key^v mod pk.n^2
    // c3 = c1 * c2 mod pk.n^2.
    var c1 = this.encryptMessage(
      pkPaillierP1,
      (rho * this.q + invk2 * m_prime) % this.q
    );

    var v = (invk2 * r * x2) % this.q;
    var c2 = this.modExp(c_key, v, pkPaillierP1.n ** 2n);
    var c3 = (c1 * c2) % pkPaillierP1.n ** 2n;

    // (d) P2 sends c3 to P1
    return { c3 };
  }
}

var walletP1 = new WalletP1(ecc, paillier);
var walletP2 = new WalletP2(ecc, paillier);

var sessionId;
function keyGeneration() {
  sessionId = crypto.randomUUID();

  // 1. P1's First Message
  const { commitmentFRDLcomZK } = walletP1.P1FirstMessage(sessionId);

  // P2 is saving the commitment message from Step 1(a)
  walletP2.receiveFRDLcomZKCommitmentKeyG(sessionId, commitmentFRDLcomZK);

  // 2. P2's First Message
  const { t2, s2, c2, Q2 } = walletP2.P2FirstMessage(sessionId);

  // P1 is saving the FRDLzk proof from p2 from Step 2(c)
  walletP1.receiveFRDLzkProofKeyG(sessionId, { t2, s2, c2, Q2 });

  // 3. P1's Second Message
  var securityParameter = 128; // 256 for stronger systems
  const { pkPaillierP1, c_key, decommitmentMessage } = walletP1.P1SecondMessage(
    sessionId,
    securityParameter
  );

  // P2 will need to store pkPaillierP1, c_key, decommitmentMessage in it
  walletP2.receiveFRDLcomZKDecommitmentKeyG(
    sessionId,
    decommitmentMessage,
    pkPaillierP1,
    c_key
  );

  // Step 4: ZK Proofs (Using Session ID)
  const zkProof = walletP1.P1ZeroKnowledgeProofs(sessionId);

  // Step 5: P2’s Verification (Using Session ID)
  const verificationResult = walletP2.P2Verification(
    sessionId,
    zkProof,
    securityParameter
  );
  if (!verificationResult) throw new Error("Verification failed");

  // Step 6: Compute the final shared public key Q
  const sharedPublicKeyP1 = walletP1.computeSharedPublicKey(sessionId);

  const sharedPublicKeyP2 = walletP2.computeSharedPublicKey(sessionId);

  // Check if the shared keys match
  if (
    !(
      sharedPublicKeyP1.x === sharedPublicKeyP2.x &&
      sharedPublicKeyP1.y === sharedPublicKeyP2.y
    )
  ) {
    throw new Error("Shared keys do not match. Key generation failed.");
  }

  console.log("SUCCESS in the key generation subprotocol");
}

keyGeneration();

function signing() {
  const message = "This is a message to be signed!";
  const m_prime = H_q(message, q);

  // 1. P1's first message
  const { signingCommitment } = walletP1.P1SigningFirstMessage(sessionId);

  // Wallet P2 receives the commitment
  walletP2.receiveSigningCommitment(sessionId, { signingCommitment });

  // 2. P2's first message
  const signingProofFRDLzk = walletP2.P2SigningFirstMessage(sessionId);

  // Wallet P1 receives the proof
  walletP1.receiveSigningProof(sessionId, signingProofFRDLzk);

  // 3. P1's second message
  const decommitmentMessage = walletP1.P1SigningSecondMessage(sessionId);

  // Wallet P2 receives the decommitment message
  walletP2.receiveSigningDecommitment(sessionId, decommitmentMessage);

  // 4. P2's second message
  const { c3 } = walletP2.P2SigningSecondMessage(sessionId, m_prime);

  // 5. P1 generates output
  const output = walletP1.P1SigningOutput(sessionId, c3, message);
  console.log("Valid signature:", output);
}

signing();

function H_q(message, q) {
  const qBitLength = q.toString(2).length; // this come from EC's q
  const hash = BigInt(
    "0x" + crypto.createHash("sha256").update(message).digest("hex")
  );
  const hashBinary = hash.toString(2).padStart(256, "0");
  const truncatedBinary = hashBinary.slice(0, qBitLength);
  return BigInt("0b" + truncatedBinary);
}
