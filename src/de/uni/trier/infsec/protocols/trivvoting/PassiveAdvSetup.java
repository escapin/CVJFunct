package de.uni.trier.infsec.protocols.trivvoting;


import de.uni.trier.infsec.environment.network.Network;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Decryptor;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Encryptor;
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

	public static void main(String[] args) throws NetworkError {

		// create the server's keys:
		Decryptor serverDec = new Decryptor();
		Encryptor serverEnc = serverDec.getEncryptor();
		Network.networkOut(serverEnc.getPublicKey()); // the public key of the server is published

		// create voters
		Voter[] voter = new Voter[Server.NumberOfVoters];
		for( int i=0; i<Server.NumberOfVoters; ++i ) {
			voter[i] = new Voter(serverEnc);
		}

		// create the server:
		Server server = new Server(serverDec);

		// the adversary determines the voters' choices (we consider here the two-candidate case)
		int[] voterChoices = new int[Server.NumberOfVoters];
		for( int i=0; i<Server.NumberOfVoters; ++i ) {
			voterChoices[i] = ( Network.networkIn()==null ? 1 : 2 );
		}

		/// TODO: COMPUTE THE IDEAL RESULT ///

		// but depending on the secret bit, the choices of the two first voters get swapped:
		if( secret ) {
			int tmp = voterChoices[0];
			voterChoices[0] = voterChoices[1];
			voterChoices[1] = tmp;
		}

		// voting (the voters create and cast their ballots directly to the server)
		for( int i=0; i<Server.NumberOfVoters; ++i ) {
			byte[] ballot = voter[i].makeBallot((byte)voterChoices[i]);  // create a ballot
			// Network.networkOut(ballot);  	// send it over the network
			server.collectBallot(i, ballot);  	// and deliver directly to the server
		}

		// output the final result:
		byte[] result = server.getResult();
		Network.networkOut(result);
	}
}

