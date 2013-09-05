package de.uni.trier.infsec.functionalities.pkienc;

import de.uni.trier.infsec.environment.RegisterEncEnv;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;

public class RegisterEnc {

	public static void registerEncryptor(Encryptor encryptor, int id, byte[] pki_domain) throws PKIError, NetworkError {
		// tell the environment/simulator what is being registered and ask if the network allows it
		if( RegisterEncEnv.register(id, pki_domain, encryptor.getPublicKey()) ) throw new NetworkError();
		if( registeredAgents.fetch(id, pki_domain) != null ) // encryptor.id is registered?
			throw new PKIError();
		registeredAgents.add(id, pki_domain, encryptor);
	}

	public static Encryptor getEncryptor(int id, byte[] pki_domain) throws PKIError, NetworkError {
		// tell the environment/simulator what is being fetched and ask if the network allows it
		if( RegisterEncEnv.getEncryptor(id, pki_domain) ) throw new NetworkError();
		Encryptor enc = registeredAgents.fetch(id, pki_domain);
		if (enc == null)
			throw new PKIError();
		return enc.copy();
	}

	/// IMPLEMENTATION 

	private static class RegisteredAgents {
		private static class EncryptorList {
			final int id;
			byte[] domain;
			Encryptor encryptor;
			EncryptorList next;
			EncryptorList(int id, byte[] domain, Encryptor encryptor, EncryptorList next) {
				this.id = id;
				this.domain = domain;
				this.encryptor= encryptor;
				this.next = next;
			}
		}

		private EncryptorList first = null;

		public void add(int id, byte[] domain, Encryptor encr) {
			first = new EncryptorList(id, domain, encr, first);
		}

		Encryptor fetch(int ID, byte[] domain) {
			for( EncryptorList node = first;  node != null;  node = node.next ) {
				if( ID == node.id && MessageTools.equal(domain, node.domain) )
					return node.encryptor;
			}
			return null;
		}
	}

	private static RegisteredAgents registeredAgents = new RegisteredAgents();

	@SuppressWarnings("serial")
	public static class PKIError extends Exception { }
}
