package examples;

import funct.pkienc.Decryptor;
import funct.pkienc.Encryptor;
import funct.pkienc.RegisterEnc;
import lib.network.NetworkError;

public class PKIEncCorruptionExample {

	static int ID_A = 1;
	static int ID_B = 2;
	static byte[] PKI_DOMAIN = {0x00, 0x04};
	static byte[] message1 = "This is a message".getBytes();
	static byte[] message2 = "This is another message".getBytes();
	static byte[] message3 = "Yet another message".getBytes();

	public static void main(String args) {

		// An honest party A can register in the following way:
		Decryptor dec_a = new Decryptor();
		Encryptor enc_a = dec_a.getEncryptor(); // enc_a is an uncorrupted encryptor
		// (Calling Decryptor.getEncryptor is the only way to obtain an uncorrupted encryptor) 
		try {
			RegisterEnc.registerEncryptor(enc_a, ID_A, PKI_DOMAIN);
		}
		catch (RegisterEnc.PKIError e) {}     // registration failed: the identifier has been already claimed.
		catch (NetworkError e) {} // or we have not got any answer

		// For a corrupted party B, we do this:
		byte [] pubk = {0x12,0x78,0x78};
		Encryptor enc_b = new Encryptor(pubk);
		try {
			RegisterEnc.registerEncryptor(enc_b, ID_B, PKI_DOMAIN);
		}
		catch (RegisterEnc.PKIError e) {}     // registration failed: the identifier has been already claimed.
		catch (NetworkError e) {} // or we have not got any answer

		// Now, somebody encrypts something for the corrupted party B:
		try {
			Encryptor encryptor_of_b = RegisterEnc.getEncryptor(ID_B, PKI_DOMAIN);
			encryptor_of_b.encrypt(message1);
			// as the encryptor of B is corrupted (is not uncorrupted), we cannot have any guarantees 
			// for what happens to message1
		}
		catch(RegisterEnc.PKIError e) {} // if ID_B has not been successfully registered, we land here
		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI

		// And now, somebody encrypts something to the uncorrupted party A:
		try {
			Encryptor encryptor_of_a = RegisterEnc.getEncryptor(ID_A, PKI_DOMAIN);
			encryptor_of_a.encrypt(message2);
		}
		catch(RegisterEnc.PKIError e) {} // if ID_B has not been successfully registered, we land here
		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI
	}

}
