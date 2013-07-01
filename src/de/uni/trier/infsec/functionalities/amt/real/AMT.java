package de.uni.trier.infsec.functionalities.amt.real;

import static de.uni.trier.infsec.utils.MessageTools.concatenate;
import static de.uni.trier.infsec.utils.MessageTools.first;
import static de.uni.trier.infsec.utils.MessageTools.second;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.pki.real.PKISig;
import de.uni.trier.infsec.functionalities.pki.real.PKISig.Signer;
import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.lib.network.NetworkServer;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Real functionality for AMT (Authenticated Message Transmission).
 * See amt.ideal.AMT for typical usage pattern.
 */
public class AMT {

	public static final byte[] DOMAIN_AMT  = new byte[] {0x01, 0x01};	
	
	//// The public interface ////

	@SuppressWarnings("serial")
	static public class AMTError extends Exception {}

	/**
	 * Pair message, sender_id.
	 *
	 * Objects of this class are returned when an agent try to read a message from its queue.
	 */
	static public class AuthenticatedMessage {
		public byte[] message;
		public int sender_id;

		private AuthenticatedMessage(byte[] message, int sender) {
			this.sender_id = sender;  this.message = message;
		}
	}

	/**
	 * Object representing an agent with all the restricted (private) data that are
	 * necessary to send and receive authenticated message.
	 */
	static public class AgentProxy
	{
		public final int ID;
		private PKISig.Signer signer;

		private AgentProxy(int id, PKISig.Signer signer) {
			this.ID = id;
			this.signer = signer;
		}

		public AuthenticatedMessage getMessage(int port) throws AMTError {
			if (registrationInProgress) throw new AMTError();
			try {
				byte[] inputMessage = NetworkServer.read(port);
				if (inputMessage == null) return null;
				// get the sender id and her verifier
				byte[] sender_id_as_bytes = MessageTools.first(inputMessage);
				int sender_id = MessageTools.byteArrayToInt(sender_id_as_bytes);
				PKISig.Verifier sender_verifier = PKISig.getVerifier(sender_id, DOMAIN_AMT);
				// retrieve the message and the signature
				byte[] signed = MessageTools.second(inputMessage);
				byte[] signature = MessageTools.first(signed);
				byte[] message_with_recipient_id = MessageTools.second(signed);
				// verify the signature
				if( ! sender_verifier.verify(signature, message_with_recipient_id) )
					return null; // invalid signature; ignore the message
				byte[] recipient_id_as_bytes = MessageTools.first(message_with_recipient_id);
				int recipient_id = MessageTools.byteArrayToInt(recipient_id_as_bytes);
				if( recipient_id != ID )
					return null; // message not intended for me
				byte[] message = MessageTools.second(message_with_recipient_id);
				return new AuthenticatedMessage(message, sender_id);
			}
			catch (NetworkError | PKIError e) {
				return null;
			}
		}

		public Channel channelTo(int recipient_id, String server, int port) throws AMTError, PKIError, NetworkError {
			if (registrationInProgress) throw new AMTError();
			return new Channel(this.ID, this.signer, recipient_id, server, port);
		}
	}

	/**
	 * Objects representing authenticated channel from sender to recipient.
	 *
	 * Such objects allow one to send a message to the recipient, where the
	 * sender is authenticated to the recipient.
	 */
	static public class Channel
	{
		private final int sender_id;
		private final int recipient_id;
		private final PKISig.Signer sender_signer;
		private final String server;
		private final int port;

		private Channel(int sender_id, PKISig.Signer sender_signer, int recipient_id, String server, int port) {
			this.sender_id = sender_id;
			this.sender_signer = sender_signer;
			this.recipient_id = recipient_id;
			this.server = server;
			this.port = port;
		}

		public void send(byte[] message) {
			byte[] recipient_id_as_bytes = MessageTools.intToByteArray(recipient_id);
			byte[] message_with_recipient_id = concatenate(recipient_id_as_bytes, message);
			byte[] signature = sender_signer.sign(message_with_recipient_id);
			byte[] signed = MessageTools.concatenate(signature, message_with_recipient_id);
			byte[] sender_id_as_bytes = MessageTools.intToByteArray(sender_id);
			byte[] outputMessage = MessageTools.concatenate(sender_id_as_bytes, signed);
			try {
				NetworkClient.send(outputMessage, server, port);
			} catch (NetworkError e) {}
		}
	}

	/**
	 * Registering an agent with the given id.
	 * If this id has been already used (registered), registration fails (the method returns null).
	 *
	 * We assume that the registration is not blocked, that is it does not ends successfully only
	 * if the given id has been already used (but not because of some network problems).
	 */
	public static AgentProxy register(int id) throws AMTError, PKIError {
		if (registrationInProgress) throw new AMTError();
		registrationInProgress = true;
		try {
			PKISig.Signer signer = new PKISig.Signer();
			PKISig.registerVerifier(signer.getVerifier(), id, DOMAIN_AMT);
			registrationInProgress = false;
			return new AgentProxy(id, signer);
		}
		catch (PKIError err) {
			registrationInProgress = false;
			throw err;
		}
		catch (NetworkError err) {
			throw new AMTError();
		}
	}

	private static boolean registrationInProgress = false;
	
	/**
	 * Method for serialization AMT AgentProxy -> Bytes
	 */
	public static byte[] agentToBytes(AgentProxy agent) {
        byte[] id = MessageTools.intToByteArray(agent.ID);
        byte[] signer = PKISig.signerToBytes(agent.signer);
        byte[] out = concatenate(id, signer);
        return out;
	}

	/**
	 * Method for serialization AMT AgentProxy <- Bytes
	 */
	public static AgentProxy agentFromBytes(byte[] bytes) {
        byte[] bId = first(bytes);
        int id = MessageTools.byteArrayToInt(bId);
        byte[] bSigner = second(bytes);

        Signer signer = PKISig.signerFromBytes(bSigner);
        AgentProxy agent = new AgentProxy(id, signer);

        return agent;
	}
	
}
