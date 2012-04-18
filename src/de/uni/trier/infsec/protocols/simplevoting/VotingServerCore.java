package de.uni.trier.infsec.protocols.simplevoting;

import de.uni.trier.infsec.functionalities.pkenc.real.Decryptor; // TODO: Change back
import de.uni.trier.infsec.functionalities.pkenc.real.Encryptor; // TODO: Change back
import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.utils.Utilities; // TODO: Remove
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
	private static int currNonce = 1;
	
	private Encryptor[] votersEnc;	// a collection of eligibe voters' public keys
	private byte[][] voterCredentials; // List of all credentials. Credentials for voters have same index as voter in votersPK
	private byte[][] ballotBox; // Takes all ballots. Ballots that have been casted have same index as voter in votersPK
	private byte[] resultVotes; // Takes all the possible choices
	private int[]   resultCount; // Takes the count for every choice
	Decryptor serverDecr; 
	
	/**
	 * The server is initialized with his decryptor and the list of (public keys of) 
	 * eligible voters.
	 */
	public VotingServerCore( Decryptor serverDecr, Encryptor[] votersEnc ) {
		// TODO [tt]: At this point we know the number of voters (votersPK.length), 
		// so we can allocate the remaining arrays once and for all (we do not need to 
		// realocate them later).
		this.votersEnc = votersEnc;
		this.serverDecr = serverDecr;
		
		voterCredentials = new byte[nonceLength][votersEnc.length];
		ballotBox = new byte[KEY_LENGTH][votersEnc.length];
		resultVotes = new byte[5];
		resultCount = new int[5];
	}
	
	/**
	 * Registration: the server generates a credential for a given voter ('voter' is 
	 * the public key of a voter), if it is not generated yet.
	 * The method returns an encrypted credential 
	 */
	public byte[] getCredential( byte[] voter ) {
		
		for (int i = 0; i < votersEnc.length; i++) {
			Encryptor voterEnc = votersEnc[i];
			byte[] voterPK = voterEnc.getPublicKey();
			
			if (!arrayEqual(voter, voterPK)) continue;
			
			// We found the voter in the list, so now check if credentials exist
			if (voterCredentials[i] != null && !arrayEmpty(voterCredentials[i])) {
				byte[] credentialEnc = voterEnc.encrypt(voterCredentials[i]);
				System.out.println(String.format("Credential looked up: %s for voter %s", 
						Utilities.byteArrayToHexString(credentialEnc), Utilities.byteArrayToHexString(voter)));
				return credentialEnc; // Credential exists
			} else {
				byte[] credential = freshCredential();
				voterCredentials[i] = credential;
				byte[] credentialEnc = voterEnc.encrypt(credential);
				System.out.println(String.format("Credential generated: %s for voter %s", 
						Utilities.byteArrayToHexString(credentialEnc), Utilities.byteArrayToHexString(voter)));
				return credentialEnc;
			}
		}
		return null; // In case the voter is unknown, return null  
	}

	/**
	 * Takes a message 'ballot' checks its well-formedness and (if it is a valid ballot
	 * of a voter who has not voted yet) collects it
	 */
	public void collectBallot( byte[] ballot ) {
		// TODO [tt] It seems that the server accpets many ballots from the same voter.
		// There should be some policy for revoting (for example, the first vote matters)
		byte[] ballotDec 	= serverDecr.decrypt(ballot); // Decrypt the ballot using servers private key
		byte[] credential 	= MessageTools.first(ballotDec); // part1 is the credential
		byte[] vote 		= MessageTools.second(ballotDec); // part2 is the vote
		
		for (int i = 0; i < voterCredentials.length; i++) {
			if (arrayEqual(voterCredentials[i], credential)) {
				ballotBox[i] = ballot;
				vote = null;
			}
		}
	}

	/**
	 * Formats the results of the election as a message and returns it.
	 */
	public byte[] getResult() {
		byte[] out = null;
		for (int i = 0; i < ballotBox.length; i++) {
			byte[] ballot = ballotBox[i];
			byte[] ballotDec = serverDecr.decrypt(ballot); 			// Decrypt the ballot using servers private key
			byte[] credential 	= MessageTools.first(ballotDec); 	// part1 is the credential
			byte vote 		= MessageTools.second(ballotDec)[0]; 	// part2 is the vote
			
			for (int j = 0; j < resultVotes.length; j++) {
				byte choice = resultVotes[j];
				if (vote == choice) {
					resultCount[i] ++;
					break;
				}
			}
		}
		for (int i = 0; i < resultVotes.length; i++) {
			// TODO: Format --> Specification needed
			// TODO [tt] List of pairs  (choice, number of votes) however encoded
		}
		
		return out;
	}
	
	
	private byte[] freshCredential() {
		return MessageTools.intToByteArray(currNonce ++); 
	}

}
