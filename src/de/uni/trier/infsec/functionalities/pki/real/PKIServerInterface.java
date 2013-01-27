package de.uni.trier.infsec.functionalities.pki.real;

import de.uni.trier.infsec.lib.network.NetworkError;


public interface PKIServerInterface {
	
	public static final byte[] MSG_GET_PUBLIC_KEY	  = new byte[]{0x08, 0x0F, 0x0D, 0x0E}; 
	public static final byte[] MSG_REGISTER 		  = new byte[]{0x07, 0x0F, 0x0D, 0x0E};
	public static final byte[] MSG_ERROR_REGISTRATION = new byte[]{0x06, 0x0F, 0x0D, 0x0E};
	
	public SignedMessage register(int id, byte[] pubKey) throws NetworkError;
	public SignedMessage getPublicKey(int id) throws NetworkError;
	public void test();
}
