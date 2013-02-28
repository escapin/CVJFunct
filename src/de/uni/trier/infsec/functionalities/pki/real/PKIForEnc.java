package de.uni.trier.infsec.functionalities.pki.real;

import de.uni.trier.infsec.lib.network.NetworkError;

public class PKIForEnc {

	public static void register(PKIEnc.Encryptor encryptor, byte[] pki_domain) throws PKIError, NetworkError {
		pki_server.register(encryptor.id, pki_domain, encryptor.getPublicKey());
	}
	
	public static boolean isRegistered(int id, byte[] pki_domain) throws NetworkError {
		try {
			pki_server.getKey(id, pki_domain);
			return true;
		}
		catch (PKIError e) {
			return false;
		}
	}
	
	public static PKIEnc.Encryptor getEncryptor(int id, byte[] pki_domain) throws PKIError, NetworkError {
		byte[] key = pki_server.getKey(id, pki_domain);
		return new PKIEnc.Encryptor(id,key);
	}
	
	/// IMPLEMENTATION ///
	private static boolean remoteMode = Boolean.parseBoolean(System.getProperty("remotemode"));
	private static PKIServerInterface pki_server = null;
	static {
		if(remoteMode) {
			pki_server = new RemotePKIServer();
			System.out.println("Working in remote mode");
		} else {
			pki_server = new PKIServerCore();
			System.out.println("Working in local mode");
		}
	}
		
}