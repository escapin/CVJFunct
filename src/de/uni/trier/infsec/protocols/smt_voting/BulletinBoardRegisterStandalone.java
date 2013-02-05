package de.uni.trier.infsec.protocols.smt_voting;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.amt.real.AMT;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AMTError;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AgentProxy;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;

public class BulletinBoardRegisterStandalone {

	public static final String PATH = System.getProperty("java.io.tmpdir") + File.separator + "smtvote" + File.separator + "bulletinBoard.amt";
	
	public static void main(String[] args) {
		System.setProperty("remotemode", Boolean.toString(true));
		BulletinBoardRegisterStandalone.start();
	}

	static BulletinBoard bb;
	
	private static void start() {
		AgentProxy proxy;
		try {
			proxy = AMT.register(Identifiers.BULLETIN_BOARD_ID);
			byte[] serialized = AMT.agentToBytes(proxy);
			storeAsFile(serialized, PATH);
		} catch (AMTError e) {
			e.printStackTrace();
		} catch (PKIError e) {
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
