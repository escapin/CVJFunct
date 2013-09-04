package de.uni.trier.infsec.environment;


public class AMTEnv {
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

	public static byte[] send(byte[] message, int sender_id, int recipient_id, String server, int port) {
		Environment.untrustedOutput(7803);
		Environment.untrustedOutputMessage(message);
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
