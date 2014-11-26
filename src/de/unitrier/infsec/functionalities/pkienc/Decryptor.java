package de.unitrier.infsec.functionalities.pkienc;

import static de.unitrier.infsec.utils.MessageTools.concatenate;
import static de.unitrier.infsec.utils.MessageTools.copyOf;
import static de.unitrier.infsec.utils.MessageTools.first;
import static de.unitrier.infsec.utils.MessageTools.second;
import de.unitrier.infsec.lib.crypto.CryptoLib;
import de.unitrier.infsec.lib.crypto.KeyPair;

/** An object encapsulating the private and public keys of some party. */
public class Decryptor {
	byte[] publicKey;
	byte[] privateKey;

	public Decryptor() {
		KeyPair keypair = CryptoLib.pke_generateKeyPair();
		this.privateKey = copyOf(keypair.privateKey);
		this.publicKey = copyOf(keypair.publicKey);
	}

	Decryptor(byte[] pubk, byte[] prvkey) {
		this.publicKey = pubk;
		this.privateKey = prvkey;
	}


	/** Decrypts 'message' with the encapsulated private key. */
	public byte[] decrypt(byte[] message) {
		return copyOf(CryptoLib.pke_decrypt(copyOf(message), copyOf(privateKey)));
	}	

	/** Returns a new encryptor object with the same public key. */
	public Encryptor getEncryptor() {
		return new Encryptor(copyOf(publicKey));
	}
	
	// Not in the ideal functionality:

	public byte[] toBytes() {
		byte[] out = concatenate(privateKey, publicKey);
		return out; 
	}

	public static Decryptor fromBytes(byte[] bytes) {
		byte[] priv = first(bytes);
		byte[] publ = second(bytes);
		Decryptor decryptor = new Decryptor(publ, priv);
		return decryptor; 
	}
	
}