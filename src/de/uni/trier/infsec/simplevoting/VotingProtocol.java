package de.uni.trier.infsec.simplevoting;

import java.util.ArrayList;

import de.uni.trier.infsec.crypto.real.CryptoException;
import de.uni.trier.infsec.crypto.real.RealLibrary;
import de.uni.trier.infsec.crypto.real.objects.Message;
import de.uni.trier.infsec.pkenc.ideal.Decryptor;
import de.uni.trier.infsec.untrusted.crypto.PublicKeyRepository;

public class VotingProtocol {
	public enum Votes {
		Candidate1, Candidate2, Candidate3
	}

	public static int VOTERS_COUNT = 10;

	private RealLibrary lib = new RealLibrary(1024 / 8, 256 / 8, 128 / 8);
	
	private ArrayList<Voter>   voterList 	= new ArrayList<Voter>();
	private ArrayList<Message> credentials 	= new ArrayList<Message>();
	private Decryptor serverEnc 			= null;

	public static void main(String[] args) throws Exception {
		VotingProtocol protocol = new VotingProtocol();
		protocol.prepareProtocol();
		protocol.run();
	}

	private void prepareProtocol() throws Exception {
		serverEnc = new Decryptor();
		PublicKeyRepository.registerPublicKey("SERVER", serverEnc.getEncryptor());

		// Generate credentials and keypairs for all users
		for (int i = 0; i < VOTERS_COUNT; i++) {
			String identifier = "Voter" + i;
			
			Decryptor privKeyVoter = new Decryptor();
			PublicKeyRepository.registerPublicKey(identifier, privKeyVoter.getEncryptor());

			// Generate credential nonce
			Message credential = lib.generateNonceMessage();
			credentials.add(credential);

			// encrypt credential using voters public interface
			Message credentialEnc = Message.getMessageFromBytes(Message.TAG_DUMMY, PublicKeyRepository.getPublicKey(identifier).encrypt(credential.getBytes()));

			// Voter gets: Random Vote, name, connection, kepair, encrypted
			// credential, servers public key
			Votes vote = Votes.values()[(int) (Math.random() * 3) % 3];
			Message mVote = lib.getMessageFromString(vote.toString());
			
			Voter voter = new Voter(lib, identifier, privKeyVoter, credentialEnc, PublicKeyRepository.getPublicKey("SERVER"), mVote);
			voterList.add(voter);
		}
		System.out.println("STARTING PROTOCOL\n");
	}

	private void run() throws Exception, InterruptedException, CryptoException {
		VotingServer server = new VotingServer(serverEnc, credentials);

		// Let all voters vote
		for (Voter voter : voterList) {
			voter.vote();
		}
		
		server.collectVotes();
	}

}
