package de.uni.trier.infsec.protocol.simplevoting;

import java.util.ArrayList;
import java.util.Hashtable;

import de.uni.trier.infsec.crypto.real.RealLibrary;
import de.uni.trier.infsec.crypto.real.objects.Message;
import de.uni.trier.infsec.network.Network;
import de.uni.trier.infsec.network.NetworkError;
import de.uni.trier.infsec.pkenc.Decryptor;
import de.uni.trier.infsec.protocol.simplevoting.VotingProtocol.Votes;

public class VotingServer {

	private ArrayList<Message> credentials = null;

	private Decryptor serverDec = null;
	private int listenTime = 0;

	private Hashtable<Message, Message> votes 	= new Hashtable<Message, Message>();
	private ArrayList<Message> ballot 			= new ArrayList<Message>();
	private Hashtable<Message, Integer> result 	= new Hashtable<Message, Integer>();

	public VotingServer(Decryptor serverDec, ArrayList<Message> credentials) {
		this.credentials = credentials;
		this.serverDec = serverDec;
	}

	public void collectVotes() throws NetworkError {
		long start = System.currentTimeMillis();
		long end = System.currentTimeMillis();

		// /////// COLLECTING VOTES /////////

		System.out.println("[SERVER]\tListening for votes: " + listenTime + "ms");
		while ((end - start) < listenTime) {
			Message in = Message.getMessageFromBytes(Message.TAG_DUMMY, Network.networkIn());
			if (in != null) {
				System.out.println("[SERVER]\tReceived vote:\t" + in.toString());
				ballot.add(in);
			}
			end = System.currentTimeMillis();
		}
		System.out.println("[SERVER]\tListening time exceeded.");

		decryptVotes();
		countAndPublish();
	}

	private void countAndPublish() {
		// ///////////////////////// COUNTING VOTES ///////////////////////////

		for (Message credential : credentials) { // check for each credential if a vote has been casted
			Message vote = votes.get(credential);

			if (vote == null) {
				System.out.println("[SERVER]\tNo vote for credential\t" + credential.toString());
				continue;
			}
			System.out.println("[SERVER]\tCounting vote for credential\t" + credential.toString());

			Integer count = result.get(vote); // Count the vote
			if (count == null) {
				count = 1;
			} else {
				count = count + 1;
			}
			System.out.println("[SERVER]\tVote for \t" + vote.toString() + "\tnew count is " + count);
			result.put(vote, count);
		}

		// ///////////////////////// GENERATING RESULTS ////////////////////////////////////

		System.out.println("\n*******************************************************");
		System.out.println("*********************** RESULTS ***********************");
		System.out.println("*******************************************************\n");

		for (Votes v : Votes.values()) { // Get the results for all possible votes
			Message vMessage = Message.getMessageFromString(Message.TAG_DUMMY, v.toString());
			System.out.println("[RESULT]\t" + v.toString() + " has " + (result.get(vMessage) == null ? "no" : result.get(vMessage)) + " votes");
		}
		System.exit(0);
	}

	private void decryptVotes() {
		// ///////////////////////// DECRYPTING VOTES ////////////////////////////////////

		votes.clear();
		for (Message m : ballot) {
			try {
				Message mDec = Message.getMessageFromBytes(Message.TAG_DUMMY, serverDec.decrypt(m.getBytes())); // Decrypt the vote using servers private key
				Message credential = RealLibrary.project0(mDec); // part1 is the credential
				Message vote = RealLibrary.project1(mDec); // part2 the choice
				
				System.out.println("[SERVER]\tCredential " + credential + " voted " + vote);

				if (votes.get(credential) != null) { // If two votes for one credential have been casted, the LAST one is used
					System.out.println("[SERVER]\tDuplicate vote for " + credential + " new vote: " + vote);
				}
				votes.put(credential, vote);
			} catch (Exception ce) {
				// An invalid vote has been casted
				System.out.println("[SERVER]\tInvalid vote has been casted. " + m.toString());
			}
		}
	}
}
