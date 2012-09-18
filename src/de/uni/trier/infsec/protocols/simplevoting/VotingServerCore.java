package de.uni.trier.infsec.protocols.simplevoting;

import de.uni.trier.infsec.functionalities.pkenc.ideal.Decryptor;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Encryptor;
import de.uni.trier.infsec.utils.MessageTools;
import static de.uni.trier.infsec.utils.Utilities.arrayEqual;
import static de.uni.trier.infsec.utils.Utilities.arrayEmpty;

/**
 * Because we do not have signatues yet, the server itself generates credentials .
 *
 * Class VotingServer should use this class (VotingServerCore) and glue it to the 
 * networking. 
 */
public class VotingServerCore {

	private static final int nonceLength = 16;
	private static final int KEY_LENGTH = 1024; 
	private static final byte[] votes = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05};
	private static int currNonce = 1;
	
	private byte[][] voterIDs;		// a collection of eligible voters' identifiers
	private Encryptor[] voterEnc;	// a collection of eligible voters' public keys; keys for voters have same index as in voterIDs
	private byte[][] voterCredentials; // List of all credentials. Credentials for voters have same index as voter in voterIDs
	private byte[][] ballotBox; // Takes all ballots. Ballots that have been casted have same index as voter in votersIDs
	private byte[] resultVotes; // Takes all the possible choices
	private int[]   resultCount; // Takes the count for every choice
	Decryptor serverDecr; 
	
	/**
	 * The server is initialized with his decryptor, the list of voters IDs and the corresponding list of
	 * voters' encryptors (public keys)
	 */
	public VotingServerCore( Decryptor serverDecr, byte[][] voterIDs, Encryptor[] voterEnc ) {
		this.voterIDs = voterIDs;
		this.voterEnc = voterEnc;
		this.serverDecr = serverDecr;
		
		voterCredentials = new byte[voterEnc.length][nonceLength];
		ballotBox = new byte[voterEnc.length][KEY_LENGTH];
		resultVotes = votes;
		resultCount = new int[5];
	}
		
	/**
	 * Registration: the server generates a credential for a given voter, if it is not generated yet.
	 * The method returns an encrypted credential 
	 */
	public byte[] getCredential( byte[] voter_id ) {
		
		for (int i = 0; i < voterIDs.length; i++) {
			if (!arrayEqual(voter_id, voterIDs[i])) continue;
			// the voter found, so (generate and) issue a credential
			if (voterCredentials[i] != null && !arrayEmpty(voterCredentials[i])) {
				byte[] credentialEnc = voterEnc[i].encrypt(voterCredentials[i]);
				return credentialEnc;
			} else {
				byte[] credential = freshCredential();
				voterCredentials[i] = credential;
				byte[] credentialEnc = voterEnc[i].encrypt(credential);
				return credentialEnc;
			}
		}
		return null; // In case the voter is unknown, return null  
	}

	/**
	 * Takes a message 'ballot' checks its well-formedness and (if it is a valid ballot
	 * of a voter who has not voted yet) collects it. If multiple votes per credential
	 * are cast, the last one counts.
	 */
	public void collectBallot( byte[] ballot ) {
		byte[] ballotDec 	= serverDecr.decrypt(ballot); 		// Decrypt the ballot using servers private key
		byte[] credential 	= MessageTools.first(ballotDec); 	// part1 is the credential
		MessageTools.second(ballotDec); // part2 is the vote
		
		for (int i = 0; i < voterCredentials.length; i++) {
			if (arrayEqual(voterCredentials[i], credential)) {
				ballotBox[i] = ballot;
			}
		}
	}

	/**
	 * Formats the results of the election as a message and returns it.
	 */
	public byte[] getResult() {
		resultCount = new int[resultCount.length];
		byte[] out = null;
		for (int i = 0; i < ballotBox.length; i++) {
			byte[] ballot = ballotBox[i];
			if (arrayEmpty(ballot)) continue;
			
			byte[] ballotDec = serverDecr.decrypt(ballot); // Decrypt the ballot using servers private key
			byte vote = MessageTools.second(ballotDec)[0]; // part2 is the vote
			
			for (int j = 0; j < resultVotes.length; j++) {
				byte choice = resultVotes[j];
				if (vote == choice) {
					resultCount[j] ++;
					break;
				}
			}
		}
		// 1st byte type code 0x09; 1 byte for choice, 4 byte for count
		out = new byte[resultVotes.length * 5];
		int idx = 0;
		for (int i = 0; i < resultVotes.length; i++) {
			out[idx++] = resultVotes[i];
			byte[] 	count = MessageTools.intToByteArray(resultCount[i]);
			for (int j = 0; j < count.length; j++) out[idx++] = count[j]; 
		}
		return out;
	}
	
	
	private byte[] freshCredential() {
		return MessageTools.intToByteArray(currNonce ++); 
	}

}
