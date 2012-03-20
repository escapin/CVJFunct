package de.uni.trier.infsec.simplevoting;

import de.uni.trier.infsec.pkenc.ideal.Decryptor;
import de.uni.trier.infsec.pkenc.ideal.Encryptor;
import de.uni.trier.infsec.untrusted.network.Network;
import de.uni.trier.infsec.utils.MessageTools;

public class Voter {
	protected Decryptor  voterDec    = null;  // secret  
	protected Encryptor  serverEnc   = null;  // public
	protected byte[] 	 credentials = null;  // secret
	protected byte[] 	 myVote 	 = null;  // secret
	

	public Voter(Decryptor voterDec, byte[] credentials, Encryptor serverEnc, byte[] mVote) {
		this.voterDec = voterDec;
		this.credentials = credentials;
		this.serverEnc = serverEnc;
		this.myVote = mVote;
	}

	public void vote() {
		try {
			// the encrypted credential gets decrypted
			byte[] credentialsDec = voterDec.decrypt(credentials); 				
			// the credential and vote are concatenated...
			byte[] out = MessageTools.concatenate(credentialsDec, myVote);  
			// ... and encrypted with the public key of the voting server
			byte[] outEnc = serverEnc.encrypt(out);		 		
			// This ciphertext is sent out (over an untrusted connection)
			Network.networkOut(outEnc);											
		} catch (Exception e) {
			// TODO
		}
	}
	
}
