package de.uni.trier.infsec.protocols.simplevoting;

import de.uni.trier.infsec.lib.network.Network;


// TODO: What does the protocol look like?
// TODO: Who should handle the decision of "protocol part"? This class or VotingServerCore 

// Protocol part 1 (retrieving credentials): 
// C -- <0x01, pubKeyClient> --> S			Request credential using Request-Code 0x01 and public Key as identifier
// S -- enc(credential, pkClient) --> C		Send encrypted credential to user

// Protocol part 2 (submitting vote):
// C -- <0x02, pubKeyClient, enc(<credential, vote>, pubKeyServer)> --> S		Submit ballot by using Request code 0x02 and 
// S -- "Some kind of acknowledge?" --> C

public class VotingServerStandalone{
	
	private class ConnectionHandler {
		public void doProtocol() {
			System.out.println("GOT CONNECTION");
			// TODO implement protocol
			Network.disconnect();
		}
	}
	
	private Thread listenThread = new Thread() {
		@Override
		public void run() {
			while (true) {
				Network.waitForClient(Network.DEFAULT_PORT);
				ConnectionHandler handler = new ConnectionHandler();
				handler.doProtocol();
			}
		}
	};
	
	public void startServer() {
		listenThread.start();
	}
	
	public static void main(String[] args) {
		VotingServerStandalone server = new VotingServerStandalone();
		server.startServer();
	}

}
