package de.uni.trier.infsec.protocols.simplevoting;

import de.uni.trier.infsec.functionalities.pkenc.real.Decryptor; // TODO: change back to ideal
import de.uni.trier.infsec.functionalities.pkenc.real.Encryptor; // TODO: change back to ideal
import de.uni.trier.infsec.utils.MessageTools;

/*
 * Voter client. It is initialized with the voter's decryptor (public/private key pair) and
 * the server's encryptor (the servers public key).  
 */
public class Voter {
	protected Decryptor  voterDec    = null;
	protected Encryptor  serverEnc   = null;
	protected byte[] 	 credential = null;

	public Voter(Decryptor voterDec, Encryptor serverEnc) {
		this.voterDec = voterDec;
		this.serverEnc = serverEnc;
	}

	public void setCredential(byte[] credential) {
		this.credential = credential;
	}
	
	public byte[] makeBallot(byte vote) {
		if (credential==null) return null; // not ready
		
		byte [] myVote = new byte[] {vote};
		// the encrypted credential gets decrypted
		byte[] credentialDec = voterDec.decrypt(credential); 				
		// the credential and vote are concatenated...
		byte[] out = MessageTools.concatenate(credentialDec, myVote);  
		// ... and encrypted with the public key of the voting server
		byte[] outEnc = serverEnc.encrypt(out);		 		
		// This ciphertext is sent out (over an untrusted connection)
		
		return outEnc;											
	}
	
}
