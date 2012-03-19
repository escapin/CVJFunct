package de.uni.trier.infsec.simplevoting;

import de.uni.trier.infsec.crypto.real.RealLibrary;
import de.uni.trier.infsec.crypto.real.objects.Message;
import de.uni.trier.infsec.pkenc.ideal.Decryptor;
import de.uni.trier.infsec.pkenc.ideal.Encryptor;
import de.uni.trier.infsec.untrusted.network.Network;

public class Voter {
	protected RealLibrary    lib     = null;
	protected String 	 identifier  = null;  // public
	protected Decryptor  voterDec    = null;  
	protected Encryptor  serverEnc   = null;  // public
	protected Message 	 credentials = null; // secret
	protected Message 	 myVote 	 = null; // secret
	

	public Voter(RealLibrary lib, String identifier, Decryptor voterDec, Message credentials, Encryptor serverEnc, Message mVote) {
		this.identifier = identifier;
		this.lib = lib;
		this.voterDec = voterDec;
		this.serverEnc = serverEnc;
		this.credentials = credentials;
		this.myVote = mVote;
	}

	public void vote() {
		try {
			print("Starting my voting");
			
			// the encrypted credential gets decrypted
			Message credentialsDec = Message.getMessageFromBytes(Message.TAG_DUMMY, voterDec.decrypt(credentials.getBytes())); 				
			// the credential and vote are concatenated...
			Message out = RealLibrary.concatenate(credentialsDec, myVote);  
			// ... and encrypted with the public key of the voting server
			Message outEnc = Message.getMessageFromBytes(Message.TAG_DUMMY, serverEnc.encrypt(out.getBytes()));		 		
			// This ciphertext is sent out (over an untrusted connection)
			Network.networkOut(outEnc.getBytes());											
			
			print("Voted successfully");
		} catch (Exception e) {
			print("An error occured while sending my vote: " + e.getLocalizedMessage());
		}
	}
	
	protected void print(String s) {
		String out = "[" + identifier.toUpperCase() + "]"; 
		System.out.println(out + "\t" + s);  
	}
}
