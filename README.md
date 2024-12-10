# Cryptography Workshop: Building a Multiparty Signature System from Scratch

## Master Cryptographic Techniques Through This Developer-Focused Series

![Cryptography Workshop Building a Myltiparty Signature System from Scratch](https://github.com/user-attachments/assets/84baa4e0-ecfc-4899-9927-b5f82446e38a)

# Introduction

This is a rigorous do-it-from-scratch article series where I cover how to implement a multiparty (of two) signing process. This technique allows two people, each contributing with his part, to build a joint signature. This application has several use cases. For instance, one person could split a private key into two shares and store each share in a different device, which diminishes the risk of having his private key compromised. Also, now it would be possible for two people to participate or use any DeFi service as long as both agree and do the work required from each side. All of this without intermediaries and using cryptography techniques as a replacement.

It is true that nowadays multiparty computation is achieved in threshold cryptography. However, when it comes to two people, there is no majority. On top of that, the current solutions require proof of knowledge and several interaction rounds, which increases the computation involved in the system. That is why Lindell, in his paper "Fast Secure Two-Party ECDSA Signing", proposes a clever implementation that is way faster and simpler than other solutions. He came up with an interesting twist in the way the cryptographic primitives are used. In his system, he combines Elliptic Curves Signing, Paillier Encryption and other advanced cryptographic concepts to create an algorithm that produces joint signatures. This article series aims to explain step by step while you build it along the way from scratch.

# Workshop

The approach of this article series is like a cryptography workshop. Expect to be challenged and learn a variety of concepts in each article. You will be asked to fill in the required code to pass each test. Each article starts with the necessary theory for each algorithm. I encourage you to stop at each section to assimilate every minute detail. This will enhance your comprehension of the cryptographic primitives. The first four articles will cover the mathematical foundations of the two-party signing system. These foundations will be inputs to implement Lindell's algorithm, which is cover in the last article. Each article series has its respective file, starter code and test, all of which are part of the [repository that you can find here](https://github.com/Blockchain-Bites/two-party-computation-signature).

# Prerequisites

The knowledge requirements for this article series are the following: elliptic curve math operations, modular arithmetic, module inverse, hash functions and discrete logarithms. Those topics are not covered. Hence, I would say if you are new to cryptography, this article series will be really challenging. In that case, I truly suggest you start here: [Cryptography for Blockchain Developers](https://www.blockchainbites.co/cryptography-for-blockchain-developers). In that course, all the prerequisites are covered in detail. Once you finish that course, you will be equipped to tackle this article series. If you already know those topics, then jump in directly.

# Article-Series List

In the pursuit of being organized, I proposed the following order for the article series:

1. [Cryptography Workshop: Building a Multiparty Signature System from Scratch - Master Cryptographic Techniques Through This Developer-Focused Series](https://medium.com/blockchain-bites-es/cryptography-workshop-building-a-myltiparty-signature-system-from-scratch-9c5efc97567a)

2. [Prove What You Know, Without Revealing Anything - A Developer’s Guide to Understanding Schnorr Proof of Knowledge](https://medium.com/@lee.marreros/prove-what-you-know-without-revealing-anything-8fc77525f761)

3. [How Two Strangers Can Share a Secret in Public - How the Diffie-Hellman Key Exchange Works, Step by Step](https://medium.com/@lee.marreros/how-two-strangers-can-share-a-secret-in-public-4a21651d9881)

4. Mastering Encryption à la Paillier - Building Additive Homomorphic Encryption from Scratch

5. Advanced Techniques in Cryptographic Protocols and Secure Multi-Party Computation

6. Two Parties, One Signature: The Future of Secure and Fast Signing - Step-by-Step Guide to Building Multiparty Signatures with Advanced Cryptography

From those articles, (1), (2) and (3) are independent, while (4) and (5) require certain algorithms from the other ones. Pay attention to the top of each file where the `require` solicits algorithms from other files. Make sure to complete all dependencies first.

# What is Blockchain Bites?

Blockchain Bites is a school for Web3 Developers. It offers rigorous and comprehensive trainings in Cryptography, Solidity, Ethereum and Blockchain in general.

# Approach

My suggestion to approach this article series is one article per week. Take your time to fully assimilate the essence of each algorithm. The very last article, rather than proposing new cryptographic concepts, proposes two subprotocols, which are part of Lindell's system. If the foundational concepts are fully comprehended, getting the gist of the subprotocols won't be that hard.

Feel free to leave a comment or ask a question wherever you see fit. Have fun and happy learning.