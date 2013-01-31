package de.uni.trier.infsec.functionalities.samt.real;

import de.uni.trier.infsec.functionalities.pki.real.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.real.PKISig;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.lib.network.NetworkServer;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Real functionality for SAMT (Secure Authenticated Message Transmission).
 * See samt.ideal.SAMT for typical usage pattern.
 */
public class SAMT {

	//// The public interface ////

	static public class SAMTError extends Exception {}

	/** 
	 * Pair message, sender_id. 
	 *
	 * Objects of this class are returned when an agent try to read a message from its queue. 
	 */
	static public class AuthenticatedMessage {
		public byte[] message;
		public int sender_id;
		public byte[] raw_input; // FIXME: remove from this variant

		private AuthenticatedMessage(byte[] message, int sender, byte[] raw_input) {
			this.sender_id = sender;  this.message = message;  this.raw_input = raw_input;
		}
	}

	/**
	 * Object representing an agent with all the restricted (private) data that are
	 * necessary to securely send and receive authenticated message.
	 * 
	 * Such an object allows one to 
	 *  - get messages from the queue or this agent (method getMessage),
	 *    where the environment decides which message is to be delivered,
	 *  - create a channel to another agent (channelTo and channelToAgent); such 
	 *    a channel can be used to securely send authenticated messages to the 
	 *    chosen agent.
	 */
	static public class AgentProxy 
	{
		public final int ID;
		private PKIEnc.Decryptor decryptor;
		private PKISig.Signer signer;

		private AgentProxy(int id, PKIEnc.Decryptor decryptor, PKISig.Signer signer) {
			this.ID = id;
			this.decryptor = decryptor;
			this.signer = signer;
		}

		public AuthenticatedMessage getMessage() throws SAMTError {
			if (registrationInProgress) throw new SAMTError();
			try {
				byte[] inputMessage = NetworkServer.read();
				// get the sender id and her verifier
				byte[] sender_id_as_bytes = MessageTools.first(inputMessage);
				int sender_id = MessageTools.byteArrayToInt(sender_id_as_bytes);
				PKISig.Verifier sender_verifier = PKISig.getVerifier(sender_id);
				// retrieve the message and the signature
				byte[] signedAndEncrypted = MessageTools.second(inputMessage);
				byte[] signed = decryptor.decrypt(signedAndEncrypted);
				byte[] signature = MessageTools.first(signed);
				byte[] message = MessageTools.second(signed);
				// verify the signature
				if( sender_verifier.verify(signature, message) )
					return new AuthenticatedMessage(message, sender_id, inputMessage);
				else
					return null; // invalid signature; ignore the message
			}
			catch (NetworkError | PKIError e) {
				return null;
			}
		}

		public Channel channelTo(int recipient_id, String server, int port) throws SAMTError, PKIError, NetworkError {
			if (registrationInProgress) throw new SAMTError();
			PKIEnc.Encryptor recipient_encryptor = PKIEnc.getEncryptor(recipient_id);
			return new Channel(this.ID, this.signer, recipient_encryptor, server, port);
		}
	}

	/**
	 * Objects representing secure and authenticated channel from sender to recipient. 
	 * 
	 * Such objects allow one to securely send a message to the recipient, where the
	 * sender is authenticated to the recipient.
	 */
	static public class Channel 
	{
		private final int sender_id;
		private final PKISig.Signer sender_signer;
		private final PKIEnc.Encryptor recipient_encryptor;
		private final String server;
		private final int port;

		private Channel(int sender_id, PKISig.Signer sender_signer, PKIEnc.Encryptor recipient_encryptor, String server, int port) {
			this.sender_id = sender_id;
			this.sender_signer = sender_signer;
			this.recipient_encryptor = recipient_encryptor;
			this.server = server;
			this.port = port;
		}		

		public byte[] send(byte[] message) {
			// sign and encrypt
			byte[] signature = sender_signer.sign(message);
			byte[] signed = MessageTools.concatenate(signature, message);
			byte[] signedAndEncrypted = recipient_encryptor.encrypt(signed);
			byte[] sender_id_as_bytes = MessageTools.intToByteArray(sender_id);
			byte[] outputMessage = MessageTools.concatenate(sender_id_as_bytes, signedAndEncrypted);
			try {
				NetworkClient.send(outputMessage, server, port);
			} catch (NetworkError e) {}
			return outputMessage; // used by the simulator for SAMT // FIXME: remove from this variant
		}
	}

	/**
	 * Registering an agent with the given id. 
	 * If this id has been already used (registered), registration fails (the method returns null).
	 *
	 * We assume that the registration is not blocked, that is it does not ends successfully only
	 * if the given id has been already used (but not because of some network problems).
	 */	
	public static AgentProxy register(int id) throws SAMTError, PKIError {
		if (registrationInProgress) throw new SAMTError();
		registrationInProgress = true;
		try {
			PKIEnc.Decryptor decryptor = PKIEnc.register(id);
			PKISig.Signer signer = PKISig.register(id);
			registrationInProgress = false;
			return new AgentProxy(id, decryptor, signer);
		}
		catch (PKIError err) {
			registrationInProgress = false;
			throw err;
		}
		catch (NetworkError err) {
			throw new SAMTError();
		}
	}

	private static boolean registrationInProgress = false;
}
