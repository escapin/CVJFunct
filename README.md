# A library of cryptographic operations

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




# The Science Behind It

For each *real functionality* (a cryptographic operation in the branch
`real`) there exists a corresponding *ideal functionality* (an idealized
version of the cryptographic operation in the branch `ideal`) so that
each real functionality **realizes** the corresponding ideal
functionality in the spirit of the simulation-based security/universal
composability (see, e.g., [[Can00][4]],[[KT13][3]]).

By establishing *noninterference* properties of a Java system running
these ideal functionalities, by the results of **[the CVJ
Framework][1]** (a framework for the Cryptographic Verification of Java
programs) we obtain strong *cryptographic indistinguishability*
properties of the same system when the ideal functionalities are
replaced by the corresponding real cryptographic operations.


A more more detailed explanation of these notions and of the CVJ
Framework as well as all the realization results of these
functionalities can be found in:

*Kuesters R. and Scapin E. and Truderung T. and Graf J.*,<br>
**[Extending and Applying a Framework for the Cryptographic Verification of Java Programs][2]**



[1]: https://eprint.iacr.org/2012/153 
[2]: https://eprint.iacr.org/2014/038 
[3]: https://eprint.iacr.org/2013/025
[4]: https://eprint.iacr.org/2000/067
