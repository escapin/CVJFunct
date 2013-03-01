package de.uni.trier.infsec.examples;

import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKISig;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIError;

public class PKISigCorruptionExample {
	static int ID_A = 1;
	static int ID_B = 2;
	static byte[] PKI_DOMAIN = {0x00, 0x04};
	static byte[] message1 = "This is a message".getBytes();
	static byte[] signature1 = {0x66,0x12};
	static byte[] message2 = "This is another message".getBytes();
	static byte[] signature2 = {0x36,0x12};
	static byte[] message3 = "Yet another message".getBytes();
	static byte[] signature3 = {0x26,0x12};
	
	public static void main(String args) {
		
		// An honest party A can register in the following way:
		PKISig.Signer sig_a = new PKISig.Signer(ID_A);
		PKISig.Verifier verif_a = sig_a.getVerifier(); // verif_a is an uncorrupted verifier
		// (this is the only way to obtain an uncorrupted verifier) 
		try {
			PKISig.register(verif_a, PKI_DOMAIN);
		}
		catch (PKIError e) {}     // registration failed: the identifier has been already claimed.
		catch (NetworkError e) {} // or we have not got any answer
		
		// For a corrupted party B, we do this:
		byte [] verif_key = {0x12,0x78,0x78};
		PKISig.Verifier verif_b = new PKISig.Verifier(ID_A, verif_key);
		try {
			PKISig.register(verif_b, PKI_DOMAIN);
		}
		catch (PKIError e) {}     // registration failed: the identifier has been already claimed.
		catch (NetworkError e) {} // or we have not got any answer

		// Now, somebody verifies something signed by the corrupted party B:
		try {
			PKISig.Verifier verif_of_b = PKISig.getVerifier(ID_B, PKI_DOMAIN);
			verif_of_b.verify(signature1, message1);
		}
		catch(PKIError e) {} // if ID_B has not been successfully registered, we land here
		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI

		// And now, somebody verifies something signed by the uncorrupted party A:
		try {
			PKISig.Verifier verif_of_a = PKISig.getVerifier(ID_A, PKI_DOMAIN);
			verif_of_a.verify(signature2, message2);
			// Verifier, as we know, is actually of type UncorruptedVerifier. So, 
			// in principle, we can obtain appropriate guarantees. This, 
			// however, may be difficult for tools.

			// To make the fact (assumption) that the verifier is uncorrupted explicit 
			// in the code, which will make it easier for the tools, we can do the following 
			// (only possible for the ideal functionality).

			PKISig.UncorruptedVerifier uncorrupted_verif_of_a = (PKISig.UncorruptedVerifier) verif_of_a;
			uncorrupted_verif_of_a.verify(signature3, message3);

			// now, we know that the code of the uncorrupted version of an encryptor is used, 
			// and so we get the guarantees of the ideal functionality.
			// Note that if the encryptor of A actually was corrupted, the cast would result in an 
			// exception and the message would not been sent (and thus, its secrecy would be preserved).
			
		}
		catch(PKIError e) {} // if ID_B has not been successfully registered, we land here
		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI
	}
}
