package de.uni.trier.infsec.proofs.smt_simulator;

import de.uni.trier.infsec.functionalities.pki_nocorrupt.PKIError;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.proofs.smt_simulator.SMT.AgentProxy;
import de.uni.trier.infsec.proofs.smt_simulator.SMT.Channel;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Simulator for ideal SAMT.
 *
 * This interface is implemented by the simulator in the realization proof.
 */
public class SMTEnv {

	public static void register(int id)	{
		try {
			AgentProxy proxy = SMT.register(id);
			agentProxies.add(proxy);
		}
		catch (PKIError | SMT.SMTError e) {}
	}

	public static boolean channelTo(int sender_id, int recipient_id, String server, int port) {
		AgentProxy sender = agentProxies.fetch(sender_id);
		try {
			Channel channel = sender.channelTo(recipient_id, server, port);
			channels.add(channel, sender_id, recipient_id, server, port);
		}
		catch (PKIError | SMT.SMTError e) {}
		catch (NetworkError e) {
			return false;
		}
		return true;
	}

	public static byte[] send(int message_length, int sender_id, int recipient_id, String server, int port) {
		Channel channel = channels.fetch(sender_id, recipient_id, server, port);
		// do the simulation (for a message of the same length)
		byte[] message = MessageTools.getZeroMessage(message_length);
		byte[] output_message = channel.send(message);
		// and additionally, record this output message (used in getMessage)
		agentProxies.getMessageQueue(recipient_id).add(output_message);
		return output_message;
	}

	public static int getMessage(int id, int port) {
		try {
			AgentProxy proxy = agentProxies.fetch(id);
			byte[] input_message = proxy.getMessage(port);
			if( input_message == null ) return -1; // no message
			int index = agentProxies.getMessageQueue(id).getIndex(input_message);
			return index;
		} catch (SMT.SMTError e) {
			return -1;
		}
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
			MessageQueue message_queue;
			final Node  next;
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

