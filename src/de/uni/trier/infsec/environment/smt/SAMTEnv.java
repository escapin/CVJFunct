package de.uni.trier.infsec.environment.smt;

import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.samt.real.SAMT;
import de.uni.trier.infsec.functionalities.samt.real.SAMT.AgentProxy;
import de.uni.trier.infsec.functionalities.samt.real.SAMT.Channel;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Simulator for ideal SAMT.
 *
 * This interface is implemented by the simulator in the realization proof.
 */
public class SAMTEnv {

	public static void register(int id)	{
		try {
			AgentProxy proxy = SAMT.register(id);
			agentProxies.add(proxy);
		}
		catch (PKIError e) {}
	}

	public static boolean channelTo(int sender_id, int recipient_id, String server, int port) {
		AgentProxy sender = agentProxies.fetch(sender_id);
		try {
			Channel channel = sender.channelTo(recipient_id, server, port);
			channels.add(channel, sender_id, recipient_id, server, port);
		}
		catch (PKIError e) {}
		catch (NetworkError e) {
			return false;
		}
		return true;
	}

	public static boolean send(int message_length, int sender_id, int recipient_id, String server, int port) {
		Channel channel = channels.fetch(sender_id, recipient_id, server, port);
		try {
			// do the simulation (for a message of the same length)
			byte[] message = MessageTools.getZeroMessage(message_length);
			byte[] output_message = channel.send(message);
			// and additionally, record this output message (used in getMessage)
			agentProxies.getMessageQueue(recipient_id).add(output_message);
			return true;
		}
		catch (NetworkError e) {
			return false;
		}
	}

	public static int getMessage(int id) {
		AgentProxy proxy = agentProxies.fetch(id);
		SAMT.AuthenticatedMessage am = proxy.getMessage();
		if( am == null ) return -1; // no message
		int index = agentProxies.getMessageQueue(id).getIndex(am.raw_input);
		return index;
	}


	////////////////////////////////////////////////////////////////////////////////////

	private static class MessageQueue 
	{
		private static class Node {
			final byte[] message;
			final Node next;

			Node(byte[] message, Node next) {
				this.message = message;
				this.next = next;
			}
		}		
		private Node first = null;

		void add(byte[] message) {
			first = new Node(message, first);
		}

		int getIndex(byte[] message) {
			Node node = first;
			for( int i=0; node!=null;  ++i ) {
				if( MessageTools.equal(message, node.message) )
					return i;
				node = node.next;
			}
			return -1;
		}
	}

	private static class ProxyList
	{
		static class Node {
			final AgentProxy agent;
			final Node  next;
			MessageQueue message_queue;
			Node(AgentProxy agent, Node next) {
				this.agent = agent;
				this.next = next;
				this.message_queue = new MessageQueue();
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

		MessageQueue getMessageQueue(int id) {
			for( Node node = first;  node != null;  node = node.next )
				if( id == node.agent.ID )
					return node.message_queue;
			return null;			
		}
	}

	private static ProxyList agentProxies;

	private static class ChannelInfo {
		final int sender_id;
		final int recipient_id;
		final String server;
		final int port;

		ChannelInfo(int sender_id, int recipient_id, String server, int port) {
			this.sender_id = sender_id;
			this.recipient_id = recipient_id;
			this.server = server;
			this.port = port;
		}
	}

	private static class ChannelList
	{
		private static class Node {
			final Channel channel;
			final ChannelInfo chinf;
			final Node  next;
			Node(Channel channel, ChannelInfo chinf, Node next) {
				this.channel = channel;
				this.chinf = chinf;
				this.next = next;
			}
		}
		private Node first = null;

		public void add(Channel channel, int sender_id, int recipient_id, String server, int port) {
			ChannelInfo chinf = new ChannelInfo(sender_id, recipient_id, server, port);
			first = new Node(channel, chinf, first);
		}

		Channel fetch(int sender_id, int recipient_id, String server, int port) {
			for( Node node = first;  node != null;  node = node.next ) {
				ChannelInfo ci = node.chinf;
				if( sender_id==ci.sender_id && recipient_id==ci.recipient_id && server.equals(ci.server) && port==ci.port )
					return node.channel;
			}
			return null;
		}
	}

	private static ChannelList channels;
}

