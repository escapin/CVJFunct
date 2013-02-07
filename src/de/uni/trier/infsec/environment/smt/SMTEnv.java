package de.uni.trier.infsec.environment.smt;


import de.uni.trier.infsec.environment.Environment;


public class SMTEnv {

	public static void register(int id)	{
		Environment.untrustedOutput(7801);
		Environment.untrustedOutput(id);
	}

	public static boolean channelTo(int sender_id, int recipient_id, String server, int port) {
		Environment.untrustedOutput(7802);
		Environment.untrustedOutput(sender_id);
		Environment.untrustedOutput(recipient_id);
		Environment.untrustedOutputString(server);
		Environment.untrustedOutput(port);
		return Environment.untrustedInput()==0;
	}

	public static byte[] send(int message_length, int sender_id, int recipient_id, String server, int port) {
		Environment.untrustedOutput(7803);
		Environment.untrustedOutput(message_length);
		Environment.untrustedOutput(sender_id);
		Environment.untrustedOutput(recipient_id);
		Environment.untrustedOutputString(server);
		Environment.untrustedOutput(port); 
		return Environment.untrustedInputMessage();
	}

	public static int getMessage(int id, int port) {
		Environment.untrustedOutput(7804);
		Environment.untrustedOutput(id);
		Environment.untrustedOutput(port);
		return Environment.untrustedInput();
	}
}
