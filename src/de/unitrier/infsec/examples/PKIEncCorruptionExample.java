package de.unitrier.infsec.examples;

import de.unitrier.infsec.functionalities.pkienc.Decryptor;
import de.unitrier.infsec.functionalities.pkienc.Encryptor;
import de.unitrier.infsec.functionalities.pkienc.RegisterEnc;
import de.unitrier.infsec.functionalities.pkienc.UncorruptedEncryptor;
import de.unitrier.infsec.lib.network.NetworkError;

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
			// Ecryptor_of_a, as we know, is actually of type UncorruptedEncryptor. So, 
			// in principle, we can obtain guarantees of secrecy of sent messages. This, 
			// however, may be difficult for tools (a tool have to see that this encryptor is
			// of this type and not of type CorruptedEncryptor).

			// To make the fact (assumption) that A is uncorrupted explicit in the code, 
			// which will make it easier for the tools, we can do the following (only possible
			// for the ideal functionality).

			UncorruptedEncryptor uncorrupted_encryptor_of_a = (UncorruptedEncryptor) encryptor_of_a;
			uncorrupted_encryptor_of_a.encrypt(message3);

			// now, we know that the code of the uncorrupted version of an encryptor is used, 
			// and so we get the guarantees of the ideal functionality.
			// Note that if the encryptor of A actually was corrupted, the cast would result in an 
			// exception and the message would not been sent (and thus, its secrecy would be preserved).

		}
		catch(RegisterEnc.PKIError e) {} // if ID_B has not been successfully registered, we land here
		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI
	}

}
