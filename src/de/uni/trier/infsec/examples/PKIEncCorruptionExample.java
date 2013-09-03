package de.uni.trier.infsec.examples;

import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.functionalities.pki.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.PKIError;

public class PKIEncCorruptionExample {

	static int ID_A = 1;
	static int ID_B = 2;
	static byte[] PKI_DOMAIN = {0x00, 0x04};
	static byte[] message1 = "This is a message".getBytes();
	static byte[] message2 = "This is another message".getBytes();
	static byte[] message3 = "Yet another message".getBytes();

	public static void main(String args) {

		// An honest party A can register in the following way:
		PKIEnc.Decryptor dec_a = new PKIEnc.Decryptor();
		PKIEnc.Encryptor enc_a = dec_a.getEncryptor(); // enc_a is an uncorrupted encryptor
		// (Calling Decryptor.getEncryptor is the only way to obtain an uncorrupted encryptor) 
		try {
			PKIEnc.registerEncryptor(enc_a, ID_A, PKI_DOMAIN);
		}
		catch (PKIError e) {}     // registration failed: the identifier has been already claimed.
		catch (NetworkError e) {} // or we have not got any answer

		// For a corrupted party B, we do this:
		byte [] pubk = {0x12,0x78,0x78};
		PKIEnc.Encryptor enc_b = new PKIEnc.Encryptor(pubk);
		try {
			PKIEnc.registerEncryptor(enc_b, ID_B, PKI_DOMAIN);
		}
		catch (PKIError e) {}     // registration failed: the identifier has been already claimed.
		catch (NetworkError e) {} // or we have not got any answer

		// Now, somebody encrypts something for the corrupted party B:
		try {
			PKIEnc.Encryptor encryptor_of_b = PKIEnc.getEncryptor(ID_B, PKI_DOMAIN);
			encryptor_of_b.encrypt(message1);
			// as the encryptor of B is corrupted (is not uncorrupted), we cannot have any guarantees 
			// for what happens to message1
		}
		catch(PKIError e) {} // if ID_B has not been successfully registered, we land here
		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI

		// And now, somebody encrypts something to the uncorrupted party A:
		try {
			PKIEnc.Encryptor encryptor_of_a = PKIEnc.getEncryptor(ID_A, PKI_DOMAIN);
			encryptor_of_a.encrypt(message2);
		}
		catch(PKIError e) {} // if ID_B has not been successfully registered, we land here
		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI
	}

}
