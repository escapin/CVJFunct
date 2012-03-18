package de.uni.trier.infsec.crypto.real.objects;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;

import de.uni.trier.infsec.crypto.real.Helper;

/**
 * Wrapper class for a message representation
 */
public class Message implements Serializable {
	private static final long serialVersionUID = 6926760493068934303L;
	
	public static final byte TAG_DUMMY	 		= 0x00;
	public static final byte TAG_PLAINTEXT 		= 0x01;
	public static final byte TAG_CONCATENATION 	= 0x02;
	public static final byte TAG_ENCRYPTION_PK 	= 0x03;
	public static final byte TAG_ENCRYPTION_SK 	= 0x04;
	public static final byte TAG_ENCRYPTION_HYB	= 0x05;
	public static final byte TAG_HASH 			= 0x06;
	public static final byte TAG_SIGNATURE 		= 0x07;
	public static final byte TAG_NONCE 			= 0x08;
	public static final byte TAG_KEY 			= 0x09;

	protected byte[] theMessage = null;

	public static Message getMessageFromBytes(byte tag, byte[] message) {
		Message m = new Message();
		if (tag == Message.TAG_DUMMY) {			
			m.setBytes(message);
		} else {			
			m.setBytesAndTag(message, tag);
		}
		return m;
	}

	public static Message getMessageFromBigInteger(byte tag, BigInteger message) {
		return getMessageFromBytes(tag, message.toByteArray());
	}

	public static Message getMessageFromHexString(byte tag, String message) {
		return getMessageFromBytes(tag, Helper.hexStringToByteArray(message));
	}

	public static Message getMessageFromString(byte tag, String message) {
		return getMessageFromBytes(tag, message.getBytes());
	}
	
	public byte[] getBytes() {
		return theMessage;
	}
	
	public byte[] getBytesWOTag() {
		byte[] stripped = new byte[theMessage.length - 1];
		System.arraycopy(theMessage, 1, stripped, 0, stripped.length);
		return stripped;
	}

	public void setBytes(byte[] message) {
		this.theMessage = message;
	}
	
	public void setBytesAndTag(byte[] message, byte tag) {
		byte[] tagged = new byte[message.length + 1];
		tagged[0] = tag;
		System.arraycopy(message, 0, tagged, 1, message.length);
		this.setBytes(tagged);
	}

	public String getAsString() {
		return new String(theMessage);
	}

	public String getAsHexString() {
		return Helper.byteArrayToHexString(theMessage);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Message)) {
			return false;
		}
		return Arrays.equals(theMessage, ((Message) obj).theMessage);
	}

	@Override
	public int hashCode() {
		return new String(theMessage).hashCode();
	}

	@Override
	public String toString() {
		return "Message: [0x]" + Helper.byteArrayToHexString(theMessage);
	}

	public int getByteLength() {
		return theMessage.length;
	}

	public void setTag(byte tag) {
		theMessage[0] = tag;
	}
	
	public byte getTag() {
		return theMessage[0];
	}

}
