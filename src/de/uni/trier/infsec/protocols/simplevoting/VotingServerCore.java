package de.uni.trier.infsec.protocols.simplevoting;

import de.uni.trier.infsec.functionalities.pkenc.ideal.Decryptor;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Encryptor;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Because we do not have signatues yet, the server itself generates credentials .
 *
 * Class VotingServer should use this class (VotingServerCore) and glue it to the 
 * networking. 
 */
public class VotingServerCore {

	private byte[][] votersPK;	// a collection of eligibe voters' public keys
	private byte[][] voterCredentials; // List of all credentials. Credentials for voters have same index as voter in votersPK
	private byte[][] ballotBox; // Takes all ballots. Ballots that have been casted have same index as voter in votersPK
	private byte[][] resultVotes; // Takes all the possible choices
	private int[]   resultCount; // Takes the count for every choice
	Decryptor serverDecr; 
	
	/**
	 * The server is initialized with his decryptor and the list of (public keys of) 
	 * eligible voters.
	 */
	public VotingServerCore( byte[][] votersPK, Decryptor serverDecr ) {
		this.votersPK = votersPK;
		this.serverDecr = serverDecr;
	}
	
	/**
	 * Registration: the server generates a credential for a given voter ('voter' is 
	 * the public key of a voter), if it is not generated yet.
	 * The method returns an encrypted credential 
	 */
	public byte[] getCredential( byte[] voter ) {
		
		for (int i = 0; i < votersPK.length; i++) {
			byte[] tmpVoter = votersPK[i];
			
			if (!arrayEqual(voter, tmpVoter)) continue;
			
			// We found the voter in the list, so now check if credentials exist
			if (voterCredentials.length <= i) {
				voterCredentials = enlargeArray(voterCredentials, i);
			}
			
			if (voterCredentials[i] != null) {
				return voterCredentials[i]; // Credential exists
			} else {
				byte[] credential = null; // createNonce(); 
				// TODO: Nonce generation -- where to put and how to generate? (length?)
				
				voterCredentials[i] = credential;
				Encryptor voterEnc = null; // new Encryptor(null, voterCredentials[i]); 
				// TODO: Visibility of Encryptor has to be public --> Need to generate Encryptor from Bytes AND set key
				
				byte[] credentialEnc = voterEnc.encrypt(credential);
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
		byte[] ballotDec = serverDecr.decrypt(ballot); // Decrypt the ballot using servers private key
		byte[] credential 	= MessageTools.first(ballotDec); // part1 is the credential
		byte[] vote 		= MessageTools.second(ballotDec); // part2 is the vote
		
		for (int i = 0; i < voterCredentials.length; i++) {
			if (arrayEqual(voterCredentials[i], credential)) {
				ballotBox = enlargeArray(ballotBox, i);
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
			byte[] vote 		= MessageTools.second(ballotDec); 	// part2 is the vote
			
			for (int j = 0; j < resultVotes.length; j++) {
				byte[] choice = resultVotes[j];
				if (arrayEqual(vote, choice)) {
					resultCount[i] ++;
					break;
				}
			}
		}
		for (int i = 0; i < resultVotes.length; i++) {
			// TODO: Format --> Specification needed			
		}
		
		return out;
	}
	
	
	
	
	
	/**
	 *	Helper to enlarge the Array which stores the credentials. Used to avoid usage of Lists 
	 */
	private byte[][] enlargeArray(byte[][] theArray, int i) {
		if (theArray.length > i) return theArray;
		
		byte[][] newArray = new byte[i+1][theArray[0].length];
		for (int j = 0; j < theArray.length; j++) {
			newArray[j] = theArray[j];
		}
		return newArray;
	}

	/**
	 *	Checks two Arrays for equality 
	 */
	private boolean arrayEqual(byte[] voter, byte[] tmpVoter) {
		if (voter.length != tmpVoter.length) return false;
		for (int i = 0; i < voter.length; i++) {
			if (voter[i] != tmpVoter[i]) return false;
		}
		return true;
	}
}
