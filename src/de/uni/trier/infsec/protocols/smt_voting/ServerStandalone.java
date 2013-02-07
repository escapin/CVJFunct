package de.uni.trier.infsec.protocols.smt_voting;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.amt.real.AMT;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AMTError;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.smt.real.SMT;
import de.uni.trier.infsec.functionalities.smt.real.SMT.SMTError;
import de.uni.trier.infsec.lib.network.NetworkError;

public class ServerStandalone {

	public static final String PATH_AMT = System.getProperty("java.io.tmpdir") + File.separator + "smtvote" + File.separator + "server.amt";
	public static final String PATH_SMT = System.getProperty("java.io.tmpdir") + File.separator + "smtvote" + File.separator + "server.smt";
	
	public static void main(String[] args) {		
		System.setProperty("remotemode", Boolean.toString(true));
		ServerStandalone.startServer();
	}

	private static void startServer() {
		SMT.AgentProxy samt_proxy;
		AMT.AgentProxy amt_proxy;
		try {
			
			byte[] serialized = readFromFile(PATH_SMT);
			samt_proxy = SMT.agentFromBytes(serialized);

			serialized = readFromFile(PATH_AMT);
			amt_proxy = AMT.agentFromBytes(serialized);
			
			Server s = new Server(samt_proxy, amt_proxy);
			while (!s.resultReady()) {
				s.onCollectBallot();
				Thread.sleep(250);
			}
			s.onPostResult();
			System.out.println("Server successfully collected all votes. Terminating.");
		} catch (SMTError e) {
			e.printStackTrace();
		} catch (PKIError e) {
			e.printStackTrace();
		} catch (AMTError e) {
			e.printStackTrace();
		} catch (NetworkError e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/*
	public static void storeAsFile(byte[] data, String sFile) throws IOException {
		File f = new File(sFile);
		File fdir = new File(sFile.substring(0, sFile.lastIndexOf(File.separator)));
		if (f.exists()) f.delete();
		fdir.mkdirs();
		f.createNewFile();
		
		FileOutputStream file = new FileOutputStream(f);
		file.write(data);
		file.flush();
		file.close();
	}
	*/
	
	private static byte[] readFromFile(String path) throws IOException {
		FileInputStream f = new FileInputStream(path);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		while (f.available() > 0){			
			bos.write(f.read());
		}
		f.close();
		byte[] data = bos.toByteArray();
		return data;
	}
	
	
}
