package de.uni.trier.infsec.functionalities.pki.idealcor;

import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.environment.network.NetworkError;

/*
 * Ideal functionality for PKI for registering of encryptors.
 * 
 * List of registered encryptors are kept locally. 
 */
public class PKIForSig {
	// FIXME: pki_domain is ignored throughout this class

	public static void register(PKISig.Verifier verifier, byte[] pki_domain) throws PKIError, NetworkError {
		if( Environment.untrustedInput() == 0 ) throw new NetworkError();
		if( isRegistered(verifier.id, pki_domain) )
			throw new PKIError();
		registeredAgents.add(verifier);
	}
	
	public static boolean isRegistered(int id, byte[] pki_domain) throws NetworkError {
		if( Environment.untrustedInput() == 0 ) throw new NetworkError();
		return registeredAgents.fetch(id) != null;
	}
	
	public static PKISig.Verifier getVerifier(int id, byte[] pki_domain) throws PKIError, NetworkError {
		if( Environment.untrustedInput() == 0 ) throw new NetworkError();
		PKISig.Verifier verif = registeredAgents.fetch(id);
		if (verif == null)
			throw new PKIError();
		return verif;
	}
	
	/// IMPLEMENTATION ///
	
	private static class RegisteredAgents {
		private static class VerifierList {
			PKISig.Verifier verifier;
			VerifierList  next;
			VerifierList(PKISig.Verifier verifier, VerifierList next) {
				this.verifier = verifier;
				this.next = next;
			}
		}

		private VerifierList first = null;
		
		public void add(PKISig.Verifier verif) {
			first = new VerifierList(verif, first);
		}
		
		PKISig.Verifier fetch(int ID) {
			for( VerifierList node = first;  node != null;  node = node.next ) {
				if( ID == node.verifier.id )
					return node.verifier;
			}
			return null;
		}
	}

	private static RegisteredAgents registeredAgents = new RegisteredAgents();
}
