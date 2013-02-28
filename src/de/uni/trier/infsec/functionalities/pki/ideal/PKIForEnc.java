package de.uni.trier.infsec.functionalities.pki.ideal;

import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.environment.network.NetworkError;

/*
 * Ideal functionality for PKI for registering of encryptors.
 * 
 * List of registered encryptors are kept locally. 
 */
public class PKIForEnc {
	// FIXME: pki_domain is ignored throughout this class

	public static void register(PKIEnc.Encryptor encryptor, byte[] pki_domain) throws PKIError, NetworkError {
		if( Environment.untrustedInput() == 0 ) throw new NetworkError();
		if( isRegistered(encryptor.id, pki_domain) )
			throw new PKIError();
		registeredAgents.add(encryptor);
	}
	
	public static boolean isRegistered(int id, byte[] pki_domain) throws NetworkError {
		if( Environment.untrustedInput() == 0 ) throw new NetworkError();
		return registeredAgents.fetch(id) != null;
	}
	
	public static PKIEnc.Encryptor getEncryptor(int id, byte[] pki_domain) throws PKIError, NetworkError {
		if( Environment.untrustedInput() == 0 ) throw new NetworkError();
		PKIEnc.Encryptor enc = registeredAgents.fetch(id);
		if (enc == null)
			throw new PKIError();
		return enc;
	}
	
	/// IMPLEMENTATION ///
	
	private static class RegisteredAgents {
		private static class EncryptorList {
			PKIEnc.Encryptor encryptor;
			EncryptorList  next;
			EncryptorList(PKIEnc.Encryptor encryptor, EncryptorList next) {
				this.encryptor= encryptor;
				this.next = next;
			}
		}

		private EncryptorList first = null;
		
		public void add(PKIEnc.Encryptor encr) {
			first = new EncryptorList(encr, first);
		}
		
		PKIEnc.Encryptor fetch(int ID) {
			for( EncryptorList node = first;  node != null;  node = node.next ) {
				if( ID == node.encryptor.id )
					return node.encryptor;
			}
			return null;
		}
	}

	private static RegisteredAgents registeredAgents = new RegisteredAgents();
}
