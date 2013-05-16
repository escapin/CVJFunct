package de.uni.trier.infsec.proofs.smt_simulator;

import static de.uni.trier.infsec.utils.MessageTools.concatenate;
import de.uni.trier.infsec.functionalities.pki.ideal.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.ideal.PKIError;
import de.uni.trier.infsec.functionalities.pki.ideal.PKISig;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.environment.network.NetworkServer;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Real functionality for SMT (Secure Authenticated Message Transmission).
 * See smt.ideal.SMT for typical usage pattern.
 */
public class SMT {
	
	//// The public interface ////

	@SuppressWarnings("serial")
	static public class SMTError extends Exception {}

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

		public byte[] getMessage(int port) throws SMTError {
			if (registrationInProgress) throw new SMTError();
			try {
				byte[] inputMessage = NetworkServer.read(port);
				if (inputMessage == null) return null;
				
				// get the sender id and her verifier
				byte[] sender_id_as_bytes = MessageTools.first(inputMessage);
				int sender_id = MessageTools.byteArrayToInt(sender_id_as_bytes);
				PKISig.Verifier sender_verifier = PKISig.getVerifier(sender_id, DOMAIN_SMT_VERIFICATION);
				// retrieve the message with the recipient id and the signature
				byte[] signedAndEncrypted = MessageTools.second(inputMessage);
				byte[] signed = decryptor.decrypt(signedAndEncrypted);
				byte[] signature = MessageTools.first(signed);
				byte[] message_with_recipient_id = MessageTools.second(signed);
				// verify the signature
				if( !sender_verifier.verify(signature, message_with_recipient_id) )
					return null; // invalid signature
				// make sure that the message is intended for this proxy
				byte[] recipient_id_as_bytes = MessageTools.first(message_with_recipient_id);
				int recipient_id = MessageTools.byteArrayToInt(recipient_id_as_bytes);
				if( recipient_id != ID )
					return null; // message not intended for this proxy
				// byte[] message = MessageTools.second(message_with_recipient_id);
				// return new AuthenticatedMessage(message, sender_id);
				return inputMessage;
			}
			catch (NetworkError | PKIError e) {
				return null;
			}
		}

		public Channel channelTo(int recipient_id, String server, int port) throws SMTError, PKIError, NetworkError {
			if (registrationInProgress) throw new SMTError();
			PKIEnc.Encryptor recipient_encryptor = PKIEnc.getEncryptor(recipient_id, DOMAIN_SMT_ENCRYPTION);
			return new Channel(this.ID, recipient_id, this.signer, recipient_encryptor, server, port);
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
		private final int recipient_id;
		private final PKISig.Signer sender_signer;
		private final PKIEnc.Encryptor recipient_encryptor;
		// private final String server;
		// private final int port;

		private Channel(int sender_id, int recipient_id,
						PKISig.Signer sender_signer, PKIEnc.Encryptor recipient_encryptor,
						String server, int port) {
			this.sender_id = sender_id;
			this.recipient_id = recipient_id;
			this.sender_signer = sender_signer;
			this.recipient_encryptor = recipient_encryptor;
			// this.server = server;
			// this.port = port;
		}		

		public byte[] send(byte[] message) {
			// sign and encrypt
			byte[] recipient_id_as_bytes = MessageTools.intToByteArray(recipient_id);
			byte[] message_with_recipient_id = concatenate(recipient_id_as_bytes, message);
			byte[] signature = sender_signer.sign(message_with_recipient_id);
			byte[] signed = MessageTools.concatenate(signature, message_with_recipient_id);
			byte[] signedAndEncrypted = recipient_encryptor.encrypt(signed);
			byte[] sender_id_as_bytes = MessageTools.intToByteArray(sender_id);
			byte[] outputMessage = MessageTools.concatenate(sender_id_as_bytes, signedAndEncrypted);
			// try {
			//	NetworkClient.send(outputMessage, server, port);
			// } catch (NetworkError e) {}
			return outputMessage; // used by the simulator
		}
	}

	/**
	 * Registering an agent with the given id. 
	 * If this id has been already used (registered), registration fails (the method returns null).
	 *
	 * We assume that the registration is not blocked, that is it does not ends successfully only
	 * if the given id has been already used (but not because of some network problems).
	 */	
	public static AgentProxy register(int id) throws SMTError, PKIError {
		if (registrationInProgress) throw new SMTError();
		registrationInProgress = true;
		try {
			PKIEnc.Decryptor decryptor = new PKIEnc.Decryptor(id);
			PKIEnc.register(decryptor.getEncryptor(), DOMAIN_SMT_ENCRYPTION);
			PKISig.Signer signer = new PKISig.Signer(id);
			PKISig.register(signer.getVerifier(), DOMAIN_SMT_VERIFICATION);
			registrationInProgress = false;
			return new AgentProxy(id, decryptor, signer);
		}
		catch (NetworkError err) {
			throw new SMTError();
		}
		catch (PKIError err) {
			registrationInProgress = false;
			throw err;
		}
	}

	private static boolean registrationInProgress = false;
		 
	public static final byte[] DOMAIN_SMT_VERIFICATION  = new byte[] {0x02, 0x01};
	public static final byte[] DOMAIN_SMT_ENCRYPTION  = new byte[] {0x02, 0x02};
}
