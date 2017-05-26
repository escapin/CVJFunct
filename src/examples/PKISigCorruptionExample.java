package examples;

import functionalities.pkisig.RegisterSig;
import functionalities.pkisig.Signer;
import functionalities.pkisig.Verifier;
import lib.network.NetworkError;

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
		Signer sig_a = new Signer();
		Verifier verif_a = sig_a.getVerifier(); // verif_a is an uncorrupted verifier
		// (this is the only way to obtain an uncorrupted verifier) 
		try {
			RegisterSig.registerVerifier(verif_a, ID_A, PKI_DOMAIN);
		}
		catch (RegisterSig.PKIError e) {}     // registration failed: the identifier has been already claimed.
		catch (NetworkError e) {} // or we have not got any answer
		
		// For a corrupted party B, we do this:
		byte [] verif_key = {0x12,0x78,0x78};
		Verifier verif_b = new Verifier(verif_key);
		try {
			RegisterSig.registerVerifier(verif_b, ID_B, PKI_DOMAIN);
		}
		catch (RegisterSig.PKIError e) {}     // registration failed: the identifier has been already claimed.
		catch (NetworkError e) {} // or we have not got any answer

		// Now, somebody verifies something signed by the corrupted party B:
		try {
			Verifier verif_of_b = RegisterSig.getVerifier(ID_B, PKI_DOMAIN);
			verif_of_b.verify(signature1, message1);
		}
		catch(RegisterSig.PKIError e) {} // if ID_B has not been successfully registered, we land here
		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI

		// And now, somebody verifies something signed by the uncorrupted party A:
		try {
			Verifier verif_of_a = RegisterSig.getVerifier(ID_A, PKI_DOMAIN);
			verif_of_a.verify(signature2, message2);
		}
		catch(RegisterSig.PKIError e) {} // if ID_B has not been successfully registered, we land here
		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI
	}
}
