package de.uni.trier.infsec.aux;

import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;

public class IdealPKI {
	static void register(int id, byte[] domain, byte[] key) throws PKIError, NetworkError {
		if (Environment.untrustedInput()==0) throw new NetworkError();
		if (registered(id, domain)) throw new PKIError();
		entries.add(id, domain, key);
	}

	static byte[] getKey(int id, byte[] domain) throws PKIError, NetworkError {
		if (Environment.untrustedInput()==0) throw new NetworkError();
		byte[] key = entries.getKey(id, domain);
		if (key == null) throw new PKIError();
		return key;
	}

	static private boolean registered(int id, byte[] domain) {
		return entries.getKey(id, domain) != null;
	}
	/// IMPLEMENTATION ///

	private static class Entry {
		final int id;
		byte[] domain;
		byte[] key;

		Entry(int id, byte[] domain, byte[] key) {
			this.id = id;
			this.domain = domain;
			this.key = key;
		}
	}

	private static class EntryList {
		private static class Node {
			Entry entry;
			Node next;
			Node(Entry entry, Node next) {
				this.entry = entry;
				this.next = next;
			}
		}

		private Node first = null;

		void add(int id, byte[] domain, byte[] key) {
			first = new Node(new Entry(id,domain,key), first);
		}

		// returns the key in the first entry with given id and domain 
		// or null if such an entry does not exists
		byte[] getKey(int id, byte[] domain) {
			for( Node node=first;  node!=null;  node = node.next ) {
				if ( node.entry.id==id &&  MessageTools.equal(node.entry.domain, domain) ) {
					return node.entry.key;
				}
			}
			return null;
		}
	}

	static private EntryList entries = new EntryList();
}
