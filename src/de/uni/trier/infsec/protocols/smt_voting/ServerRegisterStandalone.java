package de.uni.trier.infsec.protocols.smt_voting;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.amt.real.AMT;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AMTError;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.smt.real.SMT;
import de.uni.trier.infsec.functionalities.smt.real.SMT.SMTError;

public class ServerRegisterStandalone {

	public static final String PATH_AMT = System.getProperty("java.io.tmpdir") + File.separator + "smtvote" + File.separator + "server.amt";
	public static final String PATH_SMT = System.getProperty("java.io.tmpdir") + File.separator + "smtvote" + File.separator + "server.smt";
	
	public static void main(String[] args) {		
		System.setProperty("remotemode", Boolean.toString(true));
		ServerRegisterStandalone.startServer();
	}

	private static void startServer() {
		SMT.AgentProxy samt_proxy;
		try {
			samt_proxy = SMT.register(Identifiers.SERVER_ID);
			byte[] serialized = SMT.agentToBytes(samt_proxy);
			storeAsFile(serialized, PATH_SMT);
			
			AMT.AgentProxy amt_proxy  = AMT.register(Identifiers.SERVER_ID);
			serialized = AMT.agentToBytes(amt_proxy);
			storeAsFile(serialized, PATH_AMT);
		} catch (SMTError e) {
			e.printStackTrace();
		} catch (PKIError e) {
			e.printStackTrace();
		} catch (AMTError e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
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
}
