package de.uni.trier.infsec.protocols.smt_voting;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.amt.real.AMT;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AMTError;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AgentProxy;
import de.uni.trier.infsec.lib.network.NetworkServer;

public class BulletinBoardStandalone {

	public static final String PATH = System.getProperty("java.io.tmpdir") + File.separator + "smtvote" + File.separator + "bulletinBoard.amt";
	
	public static void main(String[] args) {
		System.setProperty("remotemode", Boolean.toString(true));
		BulletinBoardStandalone.start();
	}

	static BulletinBoard bb;
	
	private static void start() {
		AgentProxy proxy;
		try {
			byte[] serialized = readFromFile(PATH);
			proxy = AMT.agentFromBytes(serialized);
			
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
				
				Thread.sleep(2000);
			}
		} catch (AMTError e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	private static byte[] readFromFile(String path) throws IOException {
		FileInputStream f = new FileInputStream(path);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		while (f.available() > 0){			
			bos.write(f.read());
		}
		f.close();
		return bos.toByteArray();
	}
}
