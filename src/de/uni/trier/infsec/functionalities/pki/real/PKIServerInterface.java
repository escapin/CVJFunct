package de.uni.trier.infsec.functionalities.pki.real;

import de.uni.trier.infsec.lib.network.NetworkError;


public interface PKIServerInterface {
	// throws PKIError if the id has been already claimed.  
	void register(int id, byte[] pubKey) throws PKIError, NetworkError;
	
	// throws PKIError if id is not registered
	byte[] getPublicKey(int id) throws PKIError, NetworkError;

	// throws PKIError if the id has been already claimed.  
	void registerVerificationKey(int id, byte[] verKey) throws PKIError, NetworkError;
	
	// throws PKIError if id is not registered
	byte[] getVerificationKey(int id) throws PKIError, NetworkError;
}
