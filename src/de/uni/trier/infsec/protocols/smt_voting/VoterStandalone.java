package de.uni.trier.infsec.protocols.smt_voting;

import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.smt.real.SMT;
import de.uni.trier.infsec.functionalities.smt.real.SMT.SMTError;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.Utilities;

public class VoterStandalone {

	
	public static void main(String[] args) {
		System.setProperty("remotemode", Boolean.toString(true));
		
		if (args.length < 2) {
			System.out.println("Wrong number of Arguments!\nExpected: VoterStandalone <vote [1 byte hex]> <voter_id [int]>\nExample: VoterStandalone F0 4242");
		} else {
			try {				
				byte vote = Utilities.hexStringToByteArray(args[0])[0]; // Take first byte in case there are is more than one byte
				int id    = Integer.parseInt(args[1]);				
				VoterStandalone.doVote(vote, id);
			} catch (Exception e) {				
				System.out.println("Something is wrong with arguments.!\nExpected: VoterStandalone <vote [1 byte hex]> <voter_id [int]>\nExample: VoterStandalone F0 4242");
				e.printStackTrace();
			}
		}
	}


	private static void doVote(byte theVote, int theId) {
		try {
			SMT.AgentProxy voter_proxy = SMT.register(theId);
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
