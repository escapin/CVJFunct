package de.uni.trier.infsec.functionalities.pki.real;

import de.uni.trier.infsec.lib.network.NetworkError;

public interface PKIServer {
	// throws PKIError if the id has been already claimed.  
	void register(int id, byte[] domain, byte[] pubKey) throws PKIError, NetworkError;
	
	// throws PKIError if id is not registered
	byte[] getKey(int id, byte[] domain) throws PKIError, NetworkError;
}
