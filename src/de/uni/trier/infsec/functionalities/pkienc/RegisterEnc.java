package de.uni.trier.infsec.functionalities.pkienc;

import de.uni.trier.infsec.functionalities.pki.PKI;
import de.uni.trier.infsec.lib.network.NetworkError;


public class RegisterEnc {

	public static void registerEncryptor(Encryptor encryptor, int id, byte[] pki_domain) throws PKIError, NetworkError {
		PKI.register(id, pki_domain, encryptor.getPublicKey());
	}

	public static Encryptor getEncryptor(int id, byte[] pki_domain) throws PKIError, NetworkError {
		byte[] key = PKI.getKey(id, pki_domain);
		return new Encryptor(key);
	}

	public static final byte[] DEFAULT_PKI_DOMAIN  = new byte[] {0x03, 0x01};
}
