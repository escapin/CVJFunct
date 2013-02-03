package de.uni.trier.infsec.protocols.smt_voting;

import java.net.ServerSocket;
import java.net.Socket;

import de.uni.trier.infsec.functionalities.amt.real.AMT;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AMTError;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AgentProxy;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;

public class BulletinBoardStandalone {

	
	public static void main(String[] args) {
		System.setProperty("LISTEN_PORT", Integer.toString(Identifiers.DEFAULT_LISTEN_PORT_BBOARD));
		System.setProperty("remotemode", Boolean.toString(true));
		BulletinBoardStandalone.start();
	}

	static BulletinBoard bb;
	
	private static void start() {
		AgentProxy proxy;
		try {
			proxy = AMT.register(Identifiers.BULLETIN_BOARD_ID);
			bb = new BulletinBoard(proxy);
			Thread t = new Thread(receiveThread);
			t.start();
			
			while (true) {							
				bb.onPost();
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
	
	/**
	 * This thread is used to compute requests for contents.
	 * As we do not use an authenticated channel here, we respond any connect with the data and close the connection.
	 */
	static Runnable receiveThread = new Runnable() {
		@Override
		public void run() {
			ServerSocket ss = null;
			try {
				ss = new ServerSocket(Identifiers.DEFAULT_LISTEN_PORT_BBOARD_REQUEST);
				while (true) {
					Socket requestSocket = ss.accept();
					byte[] content = bb.onRequestContent();
					if (content != null) {						
						requestSocket.getOutputStream().write(content);
						requestSocket.getOutputStream().flush();
					}
					requestSocket.close();
				}
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				try {
					if (ss != null) ss.close();
				} catch (Exception e) {}
			}
		}
	};
}
