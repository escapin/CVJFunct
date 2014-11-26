package de.unitrier.infsec.functionalities.amt;

import static de.unitrier.infsec.utils.MessageTools.concatenate;
import static de.unitrier.infsec.utils.MessageTools.first;
import static de.unitrier.infsec.utils.MessageTools.second;
import de.unitrier.infsec.functionalities.pkisig.RegisterSig;
import de.unitrier.infsec.functionalities.pkisig.Signer;
import de.unitrier.infsec.functionalities.pkisig.Verifier;
import de.unitrier.infsec.lib.network.NetworkClient;
import de.unitrier.infsec.lib.network.NetworkError;
import de.unitrier.infsec.lib.network.NetworkServer;
import de.unitrier.infsec.utils.MessageTools;

/**
 * Real functionality for AMT (Authenticated Message Transmission).
 */
public class AMT {

	//// The public interface ////

	@SuppressWarnings("serial")
	static public class AMTError extends Exception {}

	@SuppressWarnings("serial")
	static public class RegistrationError extends Exception {}

	@SuppressWarnings("serial")
    static public class ConnectionError extends Exception {}

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

	static public class Sender 
	{
		public final int id;
		private final Signer signer;

		public void sendTo(byte[] message, int receiver_id, String server, int port) throws AMTError, ConnectionError {
			if (registrationInProgress) throw new AMTError();

			// format the message
			byte[] recipient_id_as_bytes = MessageTools.intToByteArray(receiver_id);
			byte[] message_with_recipient_id = concatenate(recipient_id_as_bytes, message);
			byte[] signature = signer.sign(message_with_recipient_id);
			byte[] signed = MessageTools.concatenate(signature, message_with_recipient_id);
			byte[] sender_id_as_bytes = MessageTools.intToByteArray(id);
			byte[] outputMessage = MessageTools.concatenate(sender_id_as_bytes, signed);

			// send it out			
			try {
				NetworkClient.send(outputMessage, server, port);
			} catch (NetworkError e) {
				throw new ConnectionError();
			}
		}

		private Sender(int id, Signer signer) {
			this.id = id;
			this.signer = signer;
		}
	}

	public static Sender registerSender(int id) throws AMTError, RegistrationError, ConnectionError {
		if (registrationInProgress) throw new AMTError();
		registrationInProgress = true;	
		try {
			// create and register a new signer 
			Signer signer = new Signer();
			RegisterSig.registerVerifier(signer.getVerifier(), id, DOMAIN_AMT);
			// registration successful; return a new Sender object
			registrationInProgress = false;
			return new Sender(id, signer);
		}
		catch (RegisterSig.PKIError err) {
			registrationInProgress = false;
			throw new RegistrationError();
		}
		catch (NetworkError err) {
			registrationInProgress = false;
			throw new ConnectionError();
		}
	}

	public static void listenOn(int port) throws ConnectionError {
		try {
			NetworkServer.listenForRequests(port);
		}
		catch (NetworkError e) {
			throw new ConnectionError();
		}
	}

	public static AuthenticatedMessage getMessage(int id, int port) throws AMTError {
		if (registrationInProgress) throw new AMTError();

		try {
			// read a message from the network
			// (it may end up with a network error)
			byte[] inputMessage = NetworkServer.read(port);
			if (inputMessage == null) return null;

			// get the sender id and her verifier
			byte[] sender_id_as_bytes = MessageTools.first(inputMessage);
			int sender_id = MessageTools.byteArrayToInt(sender_id_as_bytes);
			Verifier sender_verifier = RegisterSig.getVerifier(sender_id, DOMAIN_AMT);

			// retrieve the recipient id and the signature
			byte[] signed = MessageTools.second(inputMessage);
			byte[] signature = MessageTools.first(signed);
			byte[] message_with_recipient_id = MessageTools.second(signed);

			// verify the signature
			if( !sender_verifier.verify(signature, message_with_recipient_id) )
				return null; // invalid signature

			// make sure that the message is intended for this receiver
			byte[] recipient_id_as_bytes = MessageTools.first(message_with_recipient_id);
			int recipient_id = MessageTools.byteArrayToInt(recipient_id_as_bytes);
			if( recipient_id != id )
				return null; // message not intended for this receiver
			byte[] message = MessageTools.second(message_with_recipient_id);
			return new AuthenticatedMessage(message, sender_id);
		}
		catch (NetworkError | RegisterSig.PKIError e) {
			return null;
		}
	}


	////////////////////////////////////////////////////////////////////////////

	private static boolean registrationInProgress = false;
	public static final byte[] DOMAIN_AMT = new byte[] {0x03, 0x01};

	// Serialization Sender -> Bytes
	public static byte[] senderToBytes(Sender sender) {
		byte[] id = MessageTools.intToByteArray(sender.id);
		byte[] signer = sender.signer.toBytes();
		byte[] out = concatenate(id, signer);
		return out;
	}

	// Deserialization Sender <- Bytes
	public static Sender senderFromBytes(byte[] bytes) {
		byte[] bId = first(bytes);
		int id = MessageTools.byteArrayToInt(bId);
		byte[] bSigner = second(bytes);
		Signer signer = Signer.fromBytes(bSigner);
		return new Sender(id, signer);
	}
}
