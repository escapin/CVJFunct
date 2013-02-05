package de.uni.trier.infsec.protocols.smt_voting;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.smt.real.SMT;

public class VoterRegisterStandalone {

	public static final String PATH = System.getProperty("java.io.tmpdir") + "smtvote" + File.separator + "agent%%%%.smt";
	
	public static void main(String[] args) throws IOException {
		System.setProperty("remotemode", Boolean.toString(true));
		if (args.length < 1) {
			System.out.println("Wrong number of Arguments!\nExpected: VoterStandalone <voter_id [int]>\nExample: VoterStandalone 42");
		} else {
			try {				
				int id    = Integer.parseInt(args[0]);
				SMT.AgentProxy voter_proxy = SMT.register(id);
				byte[] serialized = SMT.agentToBytes(voter_proxy);
				storeAsFile(serialized, PATH.replaceAll("%%%%", "" + id));
			} catch (Exception e) {
				System.out.println("Something is wrong with arguments.!\nExpected: VoterStandalone <vote [1 byte hex]> <voter_id [int]>\nExample: VoterStandalone 42");
				e.printStackTrace();
			}
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
