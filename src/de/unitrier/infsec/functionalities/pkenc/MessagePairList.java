package de.unitrier.infsec.functionalities.pkenc;

import de.unitrier.infsec.utils.MessageTools;

//THIS FUNCTIONALITY IS OBSOLETE. USE PKI INSTEAD.

public class MessagePairList {
	
	static class MessagePair {
		byte[] ciphertext;
		byte[] plaintext;
		MessagePair next;
		public MessagePair(byte[] ciphertext, byte[] plaintext, MessagePair next) {
			this.ciphertext = ciphertext;
			this.plaintext = plaintext;
			this.next = next;
		}
	}
	
	private MessagePair first = null;
	
	public void add(byte[] pTxt, byte[] cTxt) {
		first = new MessagePair(cTxt, pTxt, first);
	}

    byte[] lookup(byte[] ciphertext) {
        MessagePair tmp = first;
        while( tmp != null ) {
            if( MessageTools.equal(tmp.ciphertext, ciphertext) )
                return tmp.plaintext;
            tmp = tmp.next;
        }
        return null;
    }
    
    boolean contains(byte[] ciphertext) {
        MessagePair tmp = first;
        while( tmp != null ) {
            if( MessageTools.equal(tmp.ciphertext, ciphertext) )
                return true;
            tmp = tmp.next;
        }
        return false;
    }
    
}
