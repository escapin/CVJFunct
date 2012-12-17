package de.uni.trier.infsec.functionalities.samt.real;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import de.uni.trier.infsec.environment.crypto.CryptoLib;
import de.uni.trier.infsec.environment.crypto.KeyPair;

/**
 * Real functionality for SAMT (Secure Authenticated Message Transmission).
 * See ...samt.ideal.SAMT for typical usage pattern.
 */
public class SAMT {

	//// The public interface ////

	/** 
	 * Pair message, sender_id. 
	 *
	 * Objects of this class are returned when an agent try to read a message from its queue. 
	 */
	static public class AuthenticatedMessage {
		public byte[] message;
		public int sender_id;
		public AuthenticatedMessage(byte[] message, int sender) {
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
		private int ID;
		byte[] publicKey;
		byte[] privateKey;
		byte[] verificationKey;
		byte[] signingKey;

		private AgentProxy(int id, byte[] pubKey, byte[] privKey, byte[] verifKey, byte[] signKey) {
			this.ID = id;
			this.publicKey = pubKey;
			this.privateKey = privKey;
			this.verificationKey = verifKey;
			this.signingKey = signKey;
		}

		public AuthenticatedMessage getMessage() {
			// TODO
			// (1) Somehow get a next message msg from the network.
			// (2) Check that this message contains a known identifier of some party sender.
			// (3) Fetch the verification key of the sender from PKI and using this key
			// (4) verify that the message is signed by the sender (if not, ignore the message).
			// (5) Decrypt the message using this.privateKey and
			// (6) return the result of this decryption with the identifier of the sender
			return null;
		}

		// the primary method to create a channel from this agent to the agent represented by 
		// recipient_id
		public Channel channelTo(int recipient_id, String network_address) {
			byte[] recipient_public_key = pki_getPublicKey(recipient_id);
			if (recipient_public_key == null) return null;  // there is no recipient registered with this id
			return new Channel(this.ID, this.signingKey, recipient_public_key, network_address);
		}

		// additional method that cannot be used in a distributed setting, but may be useful  
		// for verification purposes
		public Channel channelToAgent(AgentProxy recipient, String network_address) {
			return new Channel(this.ID, this.signingKey, recipient.publicKey, network_address);
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
		private int    sender_id;
		private byte[] sender_signing_key;
		private byte[] recipient_encryption_key;

		private Channel(int sender_id, byte[] sender_signing_key, 
				        byte[] recipient_encryption_key, String network_address) {
			this.sender_id = sender_id;
			this.sender_signing_key = sender_signing_key;
			this.recipient_encryption_key = recipient_encryption_key;
			// TODO: establish the network connection (assuming that the recipient is at 
			// the given network_address.
		}		

		public void send(byte[] message) {
			// TODO
			// (1) Encrypt the message with recipient_encryption_key.
			// (2) Sign it with sender_signing_key.
			// (3) Concatenate the sender_id, the signature, and the encrypted message and
			// (4) send it to the recipient.
		}
	}

	/**
	 * Registering an agent with the given id. 
	 * If this id has been already used (registered), registration fails (the method returns null).
	 */	
	public static AgentProxy register(int id) {
		KeyPair enc_keypair = CryptoLib.generateKeyPair();
		byte[] privateKey = copyOf(enc_keypair.privateKey);
		byte[] publicKey = copyOf(enc_keypair.publicKey);
		KeyPair sig_keypair = CryptoLib.generateSignatureKeyPair();
		byte[] verificationKey = copyOf(sig_keypair.publicKey);
		byte[] signingKey = copyOf(sig_keypair.privateKey);
		if( !pki_register(id, copyOf(publicKey), copyOf(verificationKey)) ) 
			return null; // registration has not succeeded (id already used)
		return new AgentProxy(id, publicKey, privateKey, verificationKey, signingKey);
	}


	//// Implementation ////

	private static boolean pki_register(int id, byte[] publicKey, byte[] verificationKey)
		{return false;}  // TODO

	private static byte[] pki_getPublicKey(int id)
		{return null;}	 // TODO

	private static byte[] pki_getVerificationKey(int id)
		{return null;}	 // TODO
}
