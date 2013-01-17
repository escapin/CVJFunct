package de.uni.trier.infsec.functionalities.amt.ideal;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import de.uni.trier.infsec.environment.Environment;

/**
 * Ideal functionality for AMT (Authenticated Message Transmission).
 *
 * Every party who wants to use this functionality should first register itself:
 *
 * 		AgentProxy a = AMT.register(ID_OF_A);
 *
 * Then, to send messages to a party with identifier ID_OF_B:
 *
 * 		Channel channel_to_b = a.channelTo(ID_OF_B);
 * 		channel_to_b.send( message1 );
 * 		channel_to_b.send( message2 );
 *
 * To read messages sent to the agent a:
 *
 * 		AuthenticatedMessage msg = a.getMessage();
 * 		// msg.message contains the received message
 * 		// msg.sender_id contains the id of the sender
 */
public class AMT {

	//// The public interface ////

	/**
	 * Pair (message, sender_id).
	 *
	 * Objects of this class are returned when an agent reads a message from its queue.
	 */
	static public class AuthenticatedMessage {
		public final byte[] message;
		public final int sender_id;
		public AuthenticatedMessage(byte[] message, int sender) {
			this.sender_id = sender;  this.message = message;
		}
	}

	/**
	 * Objects representing agents' restricted (private) data that can be used
	 * to send and receive authenticated message.
	 *
	 * Such an object allows one to
	 *  - get messages from the queue or this agent (method getMessage),
	 *    where the environment decides which message is to be delivered,
	 *  - create a channel to another agent (channelTo and channelToAgent); such
	 *    a channel can be used to send authenticated messages to the chosen agent.
	 */
	static public class AgentProxy
	{
		private final int ID;
		private final MessageQueue queue;  // messages sent to this agent

		private AgentProxy(int id) {
			this.ID = id;
			this.queue = new MessageQueue();
		}

		public AuthenticatedMessage getMessage() {
			// The environment decides which message is to be delivered.
			// Note that the same message may be delivered several times or not delivered at all.
			Environment.untrustedOutput(ID);
			int index = Environment.untrustedInput();
			return queue.get(index);
		}

		public Channel channelTo(int recipient_id) {
			AgentProxy recipient = registeredAgents.fetch(recipient_id);
			return recipient!=null ? new Channel(this,recipient) : null;
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
		private final AgentProxy sender;
		private final AgentProxy recipient;

		private Channel(AgentProxy from, AgentProxy to) {
			this.sender = from;
			this.recipient = to;
		}

		public void send(byte[] message) {
			// leak the message and the identities of the involved parties
			Environment.untrustedOutput(sender.ID);
			Environment.untrustedOutput(recipient.ID);
			Environment.untrustedOutputMessage(message);
			// add the message along with the identity of the sender to the queue of the recipient
			recipient.queue.add(copyOf(message), sender.ID);
		}
	}

	/**
	 * Registering an agent with the given id. If this id has been already used (registered),
	 * registration fails (the method returns null).
	 */
	public static AgentProxy register(int id) {
		Environment.untrustedOutput(id); // we try to register id --> adversary
		// the environment can make registration impossible (by blocking the communication)
		if(  Environment.untrustedInput() == 0 ) return null;
		// check if the id is free
		if( registeredAgents.fetch(id) != null ) {
			Environment.untrustedOutput(0); // registration unsuccessful --> adversary
			return null;
		}
		// create a new agent, add it to the list of registered agents, and return it
		AgentProxy agent = new AgentProxy(id);
		registeredAgents.add(agent);
		Environment.untrustedOutput(0); // registration successful --> adversary
		return agent;
	}


	//// Implementation ////

	//
	// MessageQueue -- a queue of messages (along with the id of the sender).
	// Such a queue is kept by an agent and represents the messages that has been
	// sent to this agent.
	//
	private static class MessageQueue
	{
		private static class Node {
			final byte[] message;
			final int sender_id;
			final Node next;
			Node(byte[] message, int sender_id, Node next) {
				this.message = message;
				this.sender_id = sender_id;
				this.next = next;
			}
		}
		private Node first = null;

		void add(byte[] message, int sender_id) {
			first = new Node(message, sender_id, first);
		}

		AuthenticatedMessage get(int index) {
			if (index<0) return null;
			Node node = first;
			for( int i=0;  i<index && node!=null;  ++i )
				node = node.next;
			return  node!=null ? new AuthenticatedMessage(copyOf(node.message), node.sender_id) : null;
		}
	}

	//
	// AgentsQueue -- a collection of registered agents.
	//
	private static class AgentsQueue
	{
		private static class Node {
			final AgentProxy agent;
			final Node  next;
			Node(AgentProxy agent, Node next) {
				this.agent = agent;
				this.next = next;
			}
		}
		private Node first = null;

		public void add(AgentProxy agent) {
			first = new Node(agent, first);
		}

		AgentProxy fetch(int id) {
			for( Node node = first;  node != null;  node = node.next )
				if( id == node.agent.ID )
					return node.agent;
			return null;
		}
	}

	// static list of registered agents:
	private static AgentsQueue registeredAgents = new AgentsQueue();
}
