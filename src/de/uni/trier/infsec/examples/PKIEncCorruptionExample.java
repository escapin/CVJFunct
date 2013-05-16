package de.uni.trier.infsec.examples;

import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.idealcor.PKIError;

public class PKIEncCorruptionExample {

	static int ID_A = 1;
	static int ID_B = 2;
	static byte[] PKI_DOMAIN = {0x00, 0x04};
	static byte[] message1 = "This is a message".getBytes();
	static byte[] message2 = "This is another message".getBytes();
	static byte[] message3 = "Yet another message".getBytes();

	public static void main(String args) {

		// An honest party A can register in the following way:
		PKIEnc.Decryptor dec_a = new PKIEnc.Decryptor(ID_A);
		PKIEnc.Encryptor enc_a = dec_a.getEncryptor(); // enc_a is an uncorrupted encryptor
		// (Calling Decryptor.getEncryptor is the only way to obtain an uncorrupted encryptor) 
		try {
			PKIEnc.register(enc_a, PKI_DOMAIN);
		}
		catch (PKIError e) {}     // registration failed: the identifier has been already claimed.
		catch (NetworkError e) {} // or we have not got any answer

		// For a corrupted party B, we do this:
		byte [] pubk = {0x12,0x78,0x78};
		PKIEnc.Encryptor enc_b = new PKIEnc.Encryptor(ID_A, pubk);
		try {
			PKIEnc.register(enc_b, PKI_DOMAIN);
		}
		catch (PKIError e) {}     // registration failed: the identifier has been already claimed.
		catch (NetworkError e) {} // or we have not got any answer

		// Now, somebody encrypts something for the corrupted party B:
		try {
			PKIEnc.Encryptor encryptor_of_b = PKIEnc.getEncryptor(ID_B, PKI_DOMAIN);
			encryptor_of_b.encrypt(message1);
			// as the encryptor of B is corrupted (in not uncorrupted), we cannot have any guarantees 
			// for what happens to message1
		}
		catch(PKIError e) {} // if ID_B has not been successfully registered, we land here
		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI

		// And now, somebody encrypts something to the uncorrupted party A:
		try {
			PKIEnc.Encryptor encryptor_of_a = PKIEnc.getEncryptor(ID_A, PKI_DOMAIN);
			encryptor_of_a.encrypt(message2);
			// Ecryptor_of_a, as we know, is actually of type UncorruptedEncryptor. So, 
			// in principle, we can obtain guarantees of secrecy of sent messages. This, 
			// however, may be difficult for tools (a tool have to see that this encryptor is
			// of this type and not of type CorruptedEncryptor).

			// To make the fact (assumption) that A is uncorrupted explicit in the code, 
			// which will make it easier for the tools, we can do the following (only possible
			// for the ideal functionality).

			PKIEnc.UncorruptedEncryptor uncorrupted_encryptor_of_a = (PKIEnc.UncorruptedEncryptor) encryptor_of_a;
			uncorrupted_encryptor_of_a.encrypt(message3);

			// now, we know that the code of the uncorrupted version of an encryptor is used, 
			// and so we get the guarantees of the ideal functionality.
			// Note that if the encryptor of A actually was corrupted, the cast would result in an 
			// exception and the message would not been sent (and thus, its secrecy would be preserved).

		}
		catch(PKIError e) {} // if ID_B has not been successfully registered, we land here
		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI
	}

}
