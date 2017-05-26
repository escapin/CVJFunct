# A collection of the most common cryptographic operations written in Java

1. Publick Key Encryption with a Public Key Infrastructure
2. Digital Signature with a Public Key Infrastructure
3. Private Symmetric Encryption
4. Nonce Generation
5. Authenticated Message Transmission: an authenticated channel to a server
6. Secure Authenticated Message Transmission: an encrypted and authenticated channel to a server

## Dependencies

* Java JDK (tested with both `openjdk-7` and `oraclejdk-8`).
* Java Cryptography Extension (only for oraclejdk).
* Bouncy Castle Cryptographic API and Test Classes (tested with `{bcprov | bctest}-jdk15on-147.jar`)
* SQLJet (tested with `sqljet-1.1.6.jar`)
* JUnit (tested with `junit-4.8.2.jar`)
* JavaParser (tested with `javaparser-1.0.8.jar`)
* Apache Ant (tested with `apache-ant-1.8.4.jar`)


The peculiarity of this implementation is that, for each cryptographic
functionality, there exists a corresponding ideal version (see branch
`ideal`) in such a way that each ideal functionality *realizes* the
corresponding real functionality in the spirit of the simulation-based
security.
See, for instance:
  - Canetti R.,
    Universally Composable Security : A New Paradigm for Cryptographic Protocols
    (https://eprint.iacr.org/2000/067)
  - Kuesters R. and Tuengerthal M.,
    The IITM Model: a Simple and Expressive Model for Universal Composability
    (https://eprint.iacr.org/2013/025)

Formal proofs of the realization results for these functionalities can be found in:
  - Kuesters R. and Scapin E. and Truderung T. and Graf J.,
    Extending and Applying a Framework for the Cryptographic Verification of Java Programs
    (https://eprint.iacr.org/2014/038)
