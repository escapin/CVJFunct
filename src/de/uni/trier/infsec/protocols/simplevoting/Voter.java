package de.uni.trier.infsec.protocols.simplevoting;

import de.uni.trier.infsec.environment.network.Network;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Decryptor;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Encryptor;
import de.uni.trier.infsec.utils.MessageTools;

public class Voter {
	protected Decryptor  voterDec    = null;
	protected Encryptor  serverEnc   = null;
	protected byte[] 	 credentials = null;
	protected byte[] 	 myVote 	 = null;

	public Voter(Decryptor voterDec, byte[] credentials, Encryptor serverEnc, byte[] mVote) {
		this.voterDec = voterDec;
		this.credentials = credentials;
		this.serverEnc = serverEnc;
		this.myVote = mVote;
	}

	public void vote() throws NetworkError {
		// the encrypted credential gets decrypted
		byte[] credentialsDec = voterDec.decrypt(credentials); 				
		// the credential and vote are concatenated...
		byte[] out = MessageTools.concatenate(credentialsDec, myVote);  
		// ... and encrypted with the public key of the voting server
		byte[] outEnc = serverEnc.encrypt(out);		 		
		// This ciphertext is sent out (over an untrusted connection)
		Network.networkOut(outEnc);											
	}
	
}
