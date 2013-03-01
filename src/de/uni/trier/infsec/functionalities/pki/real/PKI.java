package de.uni.trier.infsec.functionalities.pki.real;

import de.uni.trier.infsec.lib.network.NetworkError;

public class PKI {

	static void register(int id, byte[] domain, byte[] pubKey) throws PKIError, NetworkError {
		pki.register(id, domain, pubKey);
	}

	static byte[] getKey(int id, byte[] domain) throws PKIError, NetworkError {
		return pki.getKey(id, domain);
	}

	private static boolean remoteMode = Boolean.parseBoolean(System.getProperty("remotemode"));
	private static PKIServer pki = null;
	static {
		if(remoteMode) {
			pki = new PKIServerRemote();
			System.out.println("Working in remote mode");
		} else {
			pki = new PKIServerCore();
			System.out.println("Working in local mode");
		}
	}	
}
