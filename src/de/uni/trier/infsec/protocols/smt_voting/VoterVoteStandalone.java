package de.uni.trier.infsec.protocols.smt_voting;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.smt.real.SMT;
import de.uni.trier.infsec.functionalities.smt.real.SMT.AgentProxy;
import de.uni.trier.infsec.functionalities.smt.real.SMT.SMTError;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.Utilities;

public class VoterVoteStandalone {

	public static final String PATH = System.getProperty("java.io.tmpdir") + File.separator + "smtvote" + File.separator + "agent%%%%.smt";
	
	public static void main(String[] args) {
		System.setProperty("remotemode", Boolean.toString(true));
		if (args.length < 2) {
			System.out.println("Wrong number of Arguments!\nExpected: VoterStandalone <vote [1 byte hex]> <voter_id [int]>\nExample: VoterStandalone F0 4242");
		} else {
			try {				
				byte vote = Utilities.hexStringToByteArray(args[0])[0]; // Take first byte in case there are is more than one byte
				int id    = Integer.parseInt(args[1]);		
				byte[] serialized = readFromFile(PATH.replaceAll("%%%%", "" + id)); 
				AgentProxy agent = SMT.agentFromBytes(serialized);
				VoterVoteStandalone.doVote(vote, id, agent);
			} catch (Exception e) {				
				System.out.println("Something is wrong with arguments.!\nExpected: VoterStandalone <vote [1 byte hex]> <voter_id [int]>\nExample: VoterStandalone F0 4242");
				e.printStackTrace();
			}
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


	private static void doVote(byte theVote, int theId, SMT.AgentProxy voter_proxy) {
		try {
			Voter v = new Voter(theVote, voter_proxy);
			v.onSendBallot();
			System.out.println("Voter successfully voted. Terminating");
		} catch (SMTError e) {
			e.printStackTrace();
		} catch (PKIError e) {
			e.printStackTrace();
		} catch (NetworkError e) {
			e.printStackTrace();
		}
	}
}
