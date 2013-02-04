package de.uni.trier.infsec.protocols.smt_voting;

import de.uni.trier.infsec.functionalities.amt.real.AMT;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AMTError;
import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.utils.Utilities;

/*
 * Bulletin board on which the server can post messages (the result) and
 * everybody can retrieve the posted messages.
 */
public class BulletinBoard {

	public BulletinBoard(AMT.AgentProxy proxy) {
		content = new MessageList();
		amt_proxy = proxy;
	}

	/*
	 * Reads a message, checks if it comes from the server, and, if this is the
	 * case, adds it to the maintained list of messages.
	 */
	public void onPost() throws AMTError {
		AMT.AuthenticatedMessage am = amt_proxy.getMessage();
		if (am == null) return;
		if (am.sender_id != Identifiers.SERVER_ID) return;

		byte[] message = am.message;
		content.add(message);
		System.out.println("Received Message: " + Utilities.byteArrayToHexString(message));
	}

	/*
	 * Sends its content (that is the concatenation of all the message in the maintained
	 * list of messages) over the network.
	 */
	public byte[] onRequestContent() {
		byte[] contentMessage = {};
		for( MessageList.Node node = content.first;  node!=null;  node = node.next ) {
			contentMessage = MessageTools.concatenate(contentMessage, node.message);
		}
		return contentMessage;
	}

	/// implementation ///

	class MessageList {
		class Node {
			byte[] message;
			Node next;
			Node(byte[] message, Node next) { this.message = message; this.next = next; }
		}

		Node first = null;

		void add(byte[] message) {
			first = new Node(message, first);
		}
	}

	private MessageList content;
	private AMT.AgentProxy amt_proxy;
}
