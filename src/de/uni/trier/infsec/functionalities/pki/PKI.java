package de.uni.trier.infsec.functionalities.pki;

import de.uni.trier.infsec.lib.network.NetworkError;

public class PKI {

	static void register(int id, byte[] domain, byte[] pubKey) throws PKIError, NetworkError {
		if (pki==null)
			System.err.println("ERROR: PKI not initialized!\n Call 'useRemoteMode' or 'useLocalMode' first.");
		pki.register(id, domain, pubKey);
	}

	static byte[] getKey(int id, byte[] domain) throws PKIError, NetworkError {
		if (pki==null)
			System.err.println("ERROR: PKI not initialized!");
		return pki.getKey(id, domain);
	}

	private static PKIServer pki = null;

	public static void useRemoteMode() {
		pki = new PKIServerRemote();
		System.out.println("Working in remote mode");
	}

	public static void useLocalMode() {
		pki = new PKIServerCore();
		System.out.println("Working in local mode");
	}
}
