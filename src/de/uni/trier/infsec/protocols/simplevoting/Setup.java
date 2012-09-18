package de.uni.trier.infsec.protocols.simplevoting;

import de.uni.trier.infsec.environment.network.Network;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Decryptor;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Encryptor;
import de.uni.trier.infsec.protocols.simplevoting.VotingServerCore;
import de.uni.trier.infsec.protocols.simplevoting.Voter;
import de.uni.trier.infsec.utils.MessageTools;

/*
 * A setup for the server and (multiple) clients, for the purpose of the verification. 
 * 
 * It creates one server and some (fixed) number of voters, two of which are honest (and
 * the rest is controlled by the environment). The votes of the honest voters (given by the
 * environment) are swapped depending on the value of the secret.
 */
public class Setup {
	
	static private boolean secret = false;  // SECRET -- an arbitrary value put here
	 
	static private int NoV = 50;	// the number of voters
	static private int NoHV = 2; 	// assume that two voters are honest, the rest is controlled by the adversary
	
	
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
			voterDec[i] = new Decryptor();
			voterEnc[i] = voterDec[i].getEncryptor();
			Network.networkOut(voterEnc[i].getPublicKey()); // the public keys of voters are published
		}

		// create the server:
		VotingServerCore server = new VotingServerCore(serverDec, voterIDs, voterEnc);
		
		// create the honest voters
		Voter[] voter = new Voter[NoHV];
		for( int i=0; i<NoHV; ++i ) {
			voter[i] = new Voter( voterIDs[i], voterDec[i], serverEnc );
		}
		
		// the honest voters register successfully (encrypted credentials are, however, leaked):
		for( int i=0; i<NoHV; ++i ) {
			byte[] credential = server.getCredential(voterEnc[i].getPublicKey());
			Network.networkOut(credential);     // leak the credential
			voter[i].setCredential(credential); // give it to the voter
		}
		
		// the main loop, where the environments dictates what to do
		byte[] msg = Network.networkIn();
		while( msg != null ) { 
			// the action taken depends on the value determined by the adversary (msg[0])
			switch( msg[0] ) 
			{
			case 0: // get a credential from the server:
					byte[] credential = server.getCredential( Network.networkIn() );
					Network.networkOut(credential);
					break;

			case 1: // submit a message (as a ballot) to the server:
					server.collectBallot( Network.networkIn() );
					break;
				
			case 2: // use decryptor of a dishonest voter
					int i = MessageTools.byteArrayToInt( Network.networkIn() ); // determine the voter
					if (i>1) { // the adversary can only use decryptors of dishonest voters
						byte[] message = Network.networkIn();  
						byte[] decrypted = voterDec[i].decrypt(message);
						Network.networkOut(decrypted);
					}
					break;
								
			case 3: // honest voters -- vote
					byte v0 = Network.networkIn()[0];  // The adversary picks votes for 
					byte v1 = Network.networkIn()[0];  // the the two honest voters.
					if (secret) {  // these votes get swapped depending on the value of the secret
						byte tmp=v0; v0=v1; v1=tmp;
					}
					
					byte[] ballot0 = voter[0].makeBallot(v0);  // the ballots are created by the voters ...
					byte[] ballot1 = voter[1].makeBallot(v1); 					
					Network.networkOut( ballot0 );	// ... sent over the network ...
					Network.networkOut( ballot1 );
					server.collectBallot(ballot0);  // ... and delivered directly to the server
					server.collectBallot(ballot1);
	
					break;		
			}

			msg = Network.networkIn();
		}
		
		// output the final result:
		byte[] result = server.getResult();
		Network.networkOut(result);
	}
}
