package de.uni.trier.infsec.functionalities.pkisig;

import de.uni.trier.infsec.functionalities.pki.PKI;
import de.uni.trier.infsec.functionalities.pkienc.PKIError;
import de.uni.trier.infsec.lib.network.NetworkError;


public class RegisterSig {

	public static void registerVerifier(Verifier verifier, int id, byte[] pki_domain) throws PKIError, NetworkError {
		PKI.register(id, pki_domain, verifier.getVerifKey());
	}

	public static Verifier getVerifier(int id, byte[] pki_domain) throws PKIError, NetworkError {
		byte[] key = PKI.getKey(id, pki_domain);
		return new Verifier(key);
	}

	public static final byte[] DEFAULT_PKI_DOMAIN  = new byte[] {0x04, 0x01};
}
