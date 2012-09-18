package de.uni.trier.infsec.protocols.simplevoting;


import de.uni.trier.infsec.environment.network.Network;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Decryptor;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Encryptor;
import de.uni.trier.infsec.protocols.simplevoting.VotingServerCore;
import de.uni.trier.infsec.protocols.simplevoting.Voter;
import de.uni.trier.infsec.utils.MessageTools;

/*
 * A setup for the server and (multiple) clients with passive adversary.
 *
 * It creates one server and some (fixed) number of voters. The adversary determines the voters'
 * choices. During the voting process the adversary is passive: it gets all the sent messages,
 * but do not interfere with the process.
 */
public class PassiveAdvSetup {

	static private boolean secret = false;  // SECRET

	static private int NoV = 50;	// the number of voters (should be >= 2)

	public static void main(String[] args) throws NetworkError {

		// create the server's keys:
		Decryptor serverDec = new Decryptor();
		Encryptor serverEnc = serverDec.getEncryptor();
		Network.networkOut(serverEnc.getPublicKey()); // the public key of the server is published

		// create voters' identifiers and keys:
		byte[][]    voterIDs = new byte[NoV][];
		Decryptor[] voterDec = new Decryptor[NoV];
		Encryptor[] voterEnc = new Encryptor[NoV];
		for( int i=0; i<NoV; ++i ) {
			voterIDs[i] = MessageTools.intToByteArray(i);
			Network.networkOut(voterIDs[i]); // the voters' IDs are published
			voterDec[i] = new Decryptor();
			voterEnc[i] = voterDec[i].getEncryptor();
			Network.networkOut(voterEnc[i].getPublicKey()); // the public keys of voters are published
		}

		// create the server:
		VotingServerCore server = new VotingServerCore(serverDec, voterIDs, voterEnc);

		// create the voters
		Voter[] voter = new Voter[NoV];
		for( int i=0; i<NoV; ++i ) {
			voter[i] = new Voter( voterIDs[i], voterDec[i], serverEnc );
		}

		// the adversary determines the voters' choices (we consider here the two-candidate case)
		int[] voterChoices = new int[NoV];
		for( int i=0; i<NoV; ++i ) {
			voterChoices[i] = ( Network.networkIn()==null ? 1 : 2 );
		}
		// but depending on the secret bit, the choices of the two first voters get swapped:
		if( secret ) {
			int tmp = voterChoices[0];
			voterChoices[0] = voterChoices[1];
			voterChoices[1] = tmp;
		}

		// registration (the voters obtain their credentials)
		for( int i=0; i<NoV; ++i ) {
			byte[] credential = server.getCredential(voterIDs[i]);
			Network.networkOut(credential);     // leak the credential
			voter[i].setCredential(credential); // give it to the voter
		}

		// voting (the voters create and cast their ballots)
		for( int i=0; i<NoV; ++i ) {
			byte[] ballot = voter[i].makeBallot((byte)voterChoices[i]);  // create a ballot
			Network.networkOut(ballot);	 	// send it over the network
			server.collectBallot(ballot);  	// and deliver directly to the server
		}

		// output the final result:
		byte[] result = server.getResult();
		Network.networkOut(result);
	}
}

