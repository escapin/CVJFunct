package de.uni.trier.infsec.protocols.smt_voting;

import java.net.ServerSocket;
import java.net.Socket;

import de.uni.trier.infsec.functionalities.amt.real.AMT;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AMTError;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AgentProxy;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.lib.network.NetworkServer;

public class BulletinBoardStandalone {

	
	public static void main(String[] args) {
		System.setProperty("AMT.PORT", Integer.toString(Identifiers.DEFAULT_LISTEN_PORT_BBOARD_AMT));
		System.setProperty("SMT.PORT", Integer.toString(Identifiers.DEFAULT_LISTEN_PORT_BBOARD_SMT));
		System.setProperty("remotemode", Boolean.toString(true));
		BulletinBoardStandalone.start();
	}

	static BulletinBoard bb;
	
	private static void start() {
		AgentProxy proxy;
		try {
			proxy = AMT.register(Identifiers.BULLETIN_BOARD_ID);
			bb = new BulletinBoard(proxy);
			
			NetworkServer.listenForRequests(Identifiers.DEFAULT_LISTEN_PORT_BBOARD_REQUEST);
			
			while (true) {							
				bb.onPost();
				
				try {					
					byte[] req = NetworkServer.nextRequest(Identifiers.DEFAULT_LISTEN_PORT_BBOARD_REQUEST);
					if (req == null || req.length == 0) {
						NetworkServer.response(bb.onRequestContent());
					}
				} catch (Exception e) {e.printStackTrace();}
				
				Thread.sleep(500);
			}
		} catch (AMTError e) {
			e.printStackTrace();
		} catch (PKIError e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
