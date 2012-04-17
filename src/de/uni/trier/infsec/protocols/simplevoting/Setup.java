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
 * It creates one server and as many clients as the environments dictates.
 */
public class Setup {
	
	static private boolean secret = false;  // SECRET -- an arbitrary value put here
	 
	static private int NoV = 50;  // the number of voters
	
	
	public static void main(String[] args) throws NetworkError {

		// create the server's keys: 
		Decryptor serverDec = new Decryptor();
		Encryptor serverEnc = serverDec.getEncryptor();
		Network.networkOut(serverEnc.getPublicKey()); // the public key of the server is published
		
		// create voters' keys:
		Decryptor[] voterDec = new Decryptor[NoV];
		Encryptor[] voterEnc = new Encryptor[NoV];
		for( int i=0; i<NoV; ++i ) {
			voterDec[i] = new Decryptor();
			voterEnc[i] = voterDec[i].getEncryptor();
			Network.networkOut(voterEnc[i].getPublicKey()); // public keys of voters are published
		}

		// create the server:
		VotingServerCore server = new VotingServerCore(serverDec, voterEnc);
		
		// create the voters:
		Voter[] voter = new Voter[NoV];
		for( int i=0; i<NoV; ++i ) {
			voter[i] = new Voter( voterDec[i],  serverEnc );
		}
		
		// the main loop, where the environments dictates what to do
		byte[] msg = Network.networkIn();
		while( msg != null ) { 
			// the action taken depend on the value determined by the adversary (msg[0])
			switch( msg[0] ) {
			case 0: // server -- get a credential from the server:
					byte[] credential = server.getCredential( Network.networkIn() );
					Network.networkOut(credential);
					break;

			case 1: // server -- collect ballot:
					server.collectBallot( Network.networkIn() );
					break;
				
			case 2: // voter -- obtain a credential									
					int i = MessageTools.byteArrayToInt( Network.networkIn() ); // determine the voter
					voter[i].setCredential( Network.networkIn() );
					break;
					
			case 3: // voter -- vote
					int j = MessageTools.byteArrayToInt( Network.networkIn() ); // determine the voter
					if( j>1 ) { // the adversary decides how those voters (voter[2],voter[3],...) vote
						byte v = Network.networkIn()[0];
						byte ballot[] = voter[j].makeBallot(v);
						Network.networkOut(ballot);
					}
					else { // special case: voter[0] and voter[1] swap votes depending on the value of the secret
						byte v0 = Network.networkIn()[0];
						byte v1 = Network.networkIn()[0];
						if (secret) {
							byte tmp=v0; v0=v1; v1=tmp;
						}
						byte[] ballot0 = voter[0].makeBallot(v0);
						Network.networkOut(ballot0);
						byte[] ballot1 = voter[1].makeBallot(v1);
						Network.networkOut(ballot1);
					}
					break;		
			}

			msg = Network.networkIn();
		}
		
		// output the result:
		byte[] result = server.getResult();
		Network.networkOut(result);
	}
}
