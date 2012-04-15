package de.uni.trier.infsec.protocols.simplevoting;

import java.security.SecureRandom;
import java.util.ArrayList;

import org.bouncycastle.crypto.CryptoException;

import de.uni.trier.infsec.functionalities.pkenc.ideal.Decryptor;
import de.uni.trier.infsec.lib.crypto.PublicKeyRepository;

public class VotingProtocol {
	public enum Votes {  // TODO: What do votes look like? single Byte?
		Candidate1, Candidate2, Candidate3
	}

	public static int VOTERS_COUNT = 10;

	private ArrayList<Voter> voterList 	= new ArrayList<Voter>();
	private byte[][] credentials 		= null;
	private Decryptor serverDec 		= null;

	public static void main(String[] args) throws Exception {
		VotingProtocol protocol = new VotingProtocol();
		protocol.prepareProtocol();
		protocol.run();
	}

	private void prepareProtocol() throws Exception {
		serverDec = new Decryptor();
		PublicKeyRepository.registerPublicKey("SERVER", serverDec.getEncryptor());

		for (int i = 0; i < VOTERS_COUNT; i++) {
			String identifier = "Voter" + i;
			
			Decryptor privKeyVoter = new Decryptor();
			PublicKeyRepository.registerPublicKey(identifier, privKeyVoter.getEncryptor());

			byte[] credential = generateNonce(128);
			if (credentials == null) {
				credentials = new byte[][] {credential}; 
			} else {
				enlargeArray(credentials, credentials.length + 1);
				credentials[credentials.length -1] = credential;
			}
			Votes vote = Votes.values()[(int) (Math.random() * 3) % 3];
			byte[] credentialEnc = PublicKeyRepository.getPublicKey(identifier).encrypt(credential);
			byte mVote = vote.toString().getBytes()[0];
			Voter voter = new Voter(privKeyVoter, credentialEnc, PublicKeyRepository.getPublicKey("SERVER"), mVote);
			voterList.add(voter);
		}
		System.out.println("STARTING PROTOCOL\n");
	}

	private void run() throws Exception, InterruptedException, CryptoException {
		VotingServerCore server = new VotingServerCore(credentials, serverDec);

		for (Voter voter : voterList) {
			voter.vote();
		}
		
		server.getResult();
	}
	
	// TODO: Where to handle nonce generation?
	public static byte[] generateNonce(int length) {
		SecureRandom random = new SecureRandom();
		byte[] out = new byte[length];
		random.nextBytes(out);
		return out;
	}
	
	private byte[][] enlargeArray(byte[][] theArray, int i) {
		if (theArray.length > i) return theArray;
		
		byte[][] newArray = new byte[i+1][theArray[0].length];
		for (int j = 0; j < theArray.length; j++) {
			newArray[j] = theArray[j];
		}
		return newArray;
	}
}
