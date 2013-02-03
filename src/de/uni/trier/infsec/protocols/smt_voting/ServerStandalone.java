package de.uni.trier.infsec.protocols.smt_voting;

import de.uni.trier.infsec.functionalities.amt.real.AMT;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AMTError;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.smt.real.SMT;
import de.uni.trier.infsec.functionalities.smt.real.SMT.SMTError;
import de.uni.trier.infsec.lib.network.NetworkError;

public class ServerStandalone {

	
	public static void main(String[] args) {		
		System.setProperty("LISTEN_PORT", Integer.toString(Identifiers.DEFAULT_LISTEN_PORT_BBOARD));
		System.setProperty("remotemode", Boolean.toString(true));
		
		ServerStandalone.startServer();
	}

	private static void startServer() {
		SMT.AgentProxy samt_proxy;
		try {
			samt_proxy = SMT.register(Identifiers.SERVER_ID);
			AMT.AgentProxy amt_proxy  = AMT.register(Identifiers.SERVER_ID);
			Server s = new Server(samt_proxy, amt_proxy);
			while (!s.resultReady()) {
				s.onCollectBallot();
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
		}
	}
	
	
}
