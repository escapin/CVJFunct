package de.uni.trier.infsec.crypto.real;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.security.rsa.RSAPublicKeyImpl;
import de.uni.trier.infsec.crypto.real.objects.Message;
import de.uni.trier.infsec.crypto.real.objects.key.DecryptionKey;
import de.uni.trier.infsec.crypto.real.objects.key.EncryptionKey;
import de.uni.trier.infsec.crypto.real.objects.key.KeyPair;
import de.uni.trier.infsec.crypto.real.objects.key.SigningKey;
import de.uni.trier.infsec.crypto.real.objects.key.SigningKeyPair;
import de.uni.trier.infsec.crypto.real.objects.key.SymmetricKey;
import de.uni.trier.infsec.crypto.real.objects.key.VerificationKey;

/**
 * High level library for doing (symmetric [AES-CBC] / public-key[RSA]) encryption/decryption, digital signatures [RSA-SHA1], hashing [SHA1]
 * Uses actually BouncyCastle provider for java.crypto 
 */
public class RealLibrary {

	public static final String AES256_CBC_MODE = "aes256-cbc";
	public static final int AES_BLOCKSIZE = 16;
	public static final int DEFAULT_PK_KEYSIZE = 2048 / 8;
	public static final int DEFAULT_SK_KEYSIZE = 256 / 8;
	public static final int DEFAULT_NONCE_LENGTH = 45;

	// Specified keysize for public key encryption [byte]
	protected int pkKeySize;
	// Specified keysize for secret key encryption [byte]
	protected int skKeySize;
	// Length for nonce messages [bytes]
	protected int nonceLength;

	// ///////////////////////////////////////////////////
	// //////////////// CONSTRUCTORS /////////////////////
	// ///////////////////////////////////////////////////

	/**
	 * Constructor which allows to specify the used key lengths
	 */
	public RealLibrary(int pkKeySize, int skKeySize, int nonceLength) {
		Security.addProvider(new BouncyCastleProvider());
		this.pkKeySize = pkKeySize;
		this.skKeySize = skKeySize;
		this.nonceLength = nonceLength;
	}

	/**
	 * Default constructor
	 */
	public RealLibrary() {
		Security.addProvider(new BouncyCastleProvider());
		this.pkKeySize = DEFAULT_PK_KEYSIZE;
		this.skKeySize = DEFAULT_SK_KEYSIZE;
		this.nonceLength = DEFAULT_NONCE_LENGTH;
	}

	// /////////////////////////////////////////////////////
	// //////////////// KEY GENERATION /////////////////////
	// /////////////////////////////////////////////////////

	/**
	 * Generates a new AES KeyNote: Only 128, 192 and 256 Bit length is permitted.
	 * 
	 * @throws CryptoException
	 */
	public SymmetricKey generateSymKey() throws CryptoException {
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("AES", "BC");
			keygen.init(skKeySize * 8);
			return new SymmetricKey(keygen.generateKey());
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	/**
	 * Generates a new KeyPair Note: Minimum RSA Keylength is 512 bits.
	 * 
	 * @throws CryptoException
	 */
	public KeyPair generateKeyPair() throws CryptoException {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
			generator.initialize(pkKeySize * 8);
			KeyPair pair = new KeyPair(generator.generateKeyPair());
			return pair;
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	/**
	 * Generates a key pair for signing messages
	 * 
	 * @throws CryptoException
	 */
	public SigningKeyPair generateSigningKeyPair() throws CryptoException {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
			generator.initialize(pkKeySize * 8);
			SigningKeyPair pair = new SigningKeyPair(generator.generateKeyPair());
			return pair;
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	/**
	 * Generate inverse key for the private key. Expects RSAPrivateKey
	 * 
	 * @throws CryptoException
	 */
	public EncryptionKey getInverseKey(DecryptionKey key) throws CryptoException {

		try {
			RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) key.getPrivateKey();
			RSAPublicKey pubKey = new RSAPublicKeyImpl(privKey.getModulus(), privKey.getPublicExponent());
			return new EncryptionKey(pubKey);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}
	
	public VerificationKey getInverseKey(SigningKey key) throws CryptoException {

		try {
			RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) key.getPrivateKey();
			RSAPublicKey pubKey = new RSAPublicKeyImpl(privKey.getModulus(), privKey.getPublicExponent());
			return new VerificationKey(pubKey);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}
	

	// ///////////////////////////////////////////////////////
	// //////////////// MESSAGE HANDLING /////////////////////
	// ///////////////////////////////////////////////////////

	/**
	 * Random number generation using SecureRandom from java.security
	 */
	public BigInteger randomNumber(int byteCount) {
		SecureRandom random = new SecureRandom();
		byte[] out = new byte[byteCount];
		random.nextBytes(out);
		return new BigInteger(out);
	}

	/**
	 * Generate nonce message using randomNumber()
	 */
	public Message generateNonceMessage() {
		return Message.getMessageFromBigInteger(Message.TAG_NONCE, randomNumber(nonceLength).abs());
	}

	/**
	 * Generate Message from passed String
	 */
	public Message getMessageFromString(String string) {
		return Message.getMessageFromString(Message.TAG_PLAINTEXT, string);
	}

	// ////////////////////////////////////////////////////////////
	// //////////////// SIGNING / VERIFICATION ////////////////////
	// ////////////////////////////////////////////////////////////

	/**
	 * Signature using RSA-SHA1 Algorithm - Wrapped method for Message / Signature objects returns <sign, message>
	 * 
	 * @throws CryptoException
	 */
	public Message sign(Message input, SigningKey signingKey) throws CryptoException {
		// generate hash of the input message
		Message hash = hash(input);

		// generate encryption of messages hash
		Message signature = encPK(hash, signingKey);

		Message concatenation = concatenate(signature, input);
		concatenation.setTag(Message.TAG_SIGNATURE);
		return concatenation;
	}

	/**
	 * Validation of the Signature object, checks if the signature is valid for the contained message using the given public key
	 * 
	 * @throws CryptoException
	 */
	public boolean validateSignature(Message input, VerificationKey pubKey) throws CryptoException {
		Message signature = null;
		Message message = null;

		// Maybe we get a Signed-Object so we can just use the getter method
		signature = project0(input);
		message = project1(input);

		// decrypt signature using public key
		Message signDec = decPK(signature, pubKey);

		// hash the original message
		Message hash = hash(message);

		// check for equality
		return (hash.equals(signDec));
	}

	// //////////////////////////////////////////////
	// //////////////// HASHING /////////////////////
	// //////////////////////////////////////////////

	/**
	 * Wrapper for the SHA1 hashing
	 * 
	 * @throws CryptoException
	 */
	public Message hash(Message message) throws CryptoException {
		return Message.getMessageFromBytes(Message.TAG_HASH, hash(message.getBytesWOTag()));
	}

	/**
	 * generates a SHA1 hash for the given input
	 * 
	 * @throws CryptoException
	 */
	private byte[] hash(byte[] input) throws CryptoException {
		try {
			MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
			hash.update(input);
			byte[] digest = hash.digest();
			hash.reset();
			return digest;
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	// /////////////////////////////////////////////////////////////////
	// //////////////// CONCATENATION / PROJECTION /////////////////////
	// /////////////////////////////////////////////////////////////////

	/**
	 * Concatenation of the bit vectors within the messages. Structure of the generated data: 1 Byte Identifier [0x01], 4 Byte length of m1, m1, m2
	 */

	public static Message concatenate(Message m1, Message m2) {
		// Concatenated Message --> byte[0] = Type, byte[1-4] = BigInteger,
		// Length of Message 1
		byte[] tmp = new byte[m1.getByteLength() + m2.getByteLength() + 4];

		// 4 bytes for length
		byte[] len = Helper.intToByteArray(m1.getByteLength());

		// After all, copy all bytes to output array
		System.arraycopy(len, 0, tmp, 0, 4);
		System.arraycopy(m1.getBytes(), 0, tmp, 4, m1.getByteLength());
		System.arraycopy(m2.getBytes(), 0, tmp, 4 + m1.getByteLength(), m2.getByteLength());

		Message out = Message.getMessageFromBytes(Message.TAG_CONCATENATION, tmp);
		return out;
	}

	/**
	 * Projection of the message to its two parts (part 1 = position 0, part 2 = position 1) Structure of the expected data: 1 Byte Identifier [0x01], 4 Byte
	 * length of m1, m1, m2
	 */

	private static Message project(Message message, int position) {
		byte[] rawMessage = message.getBytesWOTag();

		// integer, Length of Message 1
		byte[] length = new byte[4];
		System.arraycopy(rawMessage, 0, length, 0, 4);
		int len = Helper.byteArrayToInt(length);

		if (position == 0) {
			byte[] m1 = new byte[len];
			System.arraycopy(rawMessage, 4, m1, 0, len);
			return Message.getMessageFromBytes(Message.TAG_DUMMY, m1);
		} else if (position == 1) {
			byte[] m2 = new byte[rawMessage.length - len - 4];
			System.arraycopy(rawMessage, 4 + len, m2, 0, rawMessage.length - len - 4);
			return Message.getMessageFromBytes(Message.TAG_DUMMY, m2);
		}
		return null;
	}

	public static Message project0(Message in) {
		return project(in, 0);
	}

	public static Message project1(Message in) {
		return project(in, 1);
	}

	/**
	 * Comparison of twos messages contents
	 */
	public boolean equal(Message m1, Message m2) {
		return equals(m1.getBytes(), m2.getBytes());
	}

	/**
	 * comparison of two bit vectors
	 */
	private boolean equals(byte[] m1, byte[] m2) {
		return Arrays.equals(m1, m2);
	}

	// ///////////////////////////////////////////////////////////
	// //////////////// SYMMETRIC ENCRYPTION /////////////////////
	// ///////////////////////////////////////////////////////////

	/**
	 * Encryption using AES256_CBC (No other mode available yet) Encoding: |-- 4Bytes padding.len --|-- padding zeros --|-- message --|
	 * 
	 * @throws CryptoException
	 */
	public Message encSym(Message message, SymmetricKey key) throws CryptoException {
		byte[] rawOut = encAES(message.getBytes(), key.getKey().getEncoded());
		return Message.getMessageFromBytes(Message.TAG_ENCRYPTION_SK, rawOut);
	}

	/**
	 * Encryption using AES256_CBC (No other mode available yet) Data is expected as multiple of block size --> Padding has to be done before
	 * 
	 * @throws CryptoException
	 */
	private byte[] encAES(byte[] input, byte[] keyBytes) throws CryptoException {
		try {
			byte[] ivBytes = randomNumber(AES_BLOCKSIZE).toByteArray();

			KeyParameter keyParam = new KeyParameter(keyBytes);
			CipherParameters params = new ParametersWithIV(keyParam, ivBytes);
			BlockCipherPadding padding = new PKCS7Padding();

			PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding);
			cipher.init(true, params);
			int len = 0;
			byte[] output = new byte[cipher.getOutputSize(input.length)];
			byte[] outputIV = new byte[cipher.getOutputSize(input.length) + AES_BLOCKSIZE];

			len = cipher.processBytes(input, 0, input.length, output, 0);
			len += cipher.doFinal(output, len);
			System.arraycopy(ivBytes, 0, outputIV, 0, AES_BLOCKSIZE);
			System.arraycopy(output, 0, outputIV, AES_BLOCKSIZE, output.length);
			return outputIV;
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	// ///////////////////////////////////////////////////////////
	// //////////////// SYMMETRIC DECRYPTION /////////////////////
	// ///////////////////////////////////////////////////////////

	/**
	 * Decryption using AES256_CBC (No other mode available yet)
	 * @throws CryptoException 
	 */
	public Message decSym(Message input, SymmetricKey key) throws CryptoException {
		byte[] dec;
		try {
			dec = decAES(input.getBytesWOTag(), key.getKey().getEncoded());
		} catch (Exception e) {
			throw new CryptoException(e);
		}
		return Message.getMessageFromBytes(Message.TAG_DUMMY, dec);
	}

	/**
	 * Decryption using AES256_CBC (No other mode available yet) Expected encoding: |-- 4Bytes padding.len --|-- padding zeros --|-- message --|
	 * @throws InvalidCipherTextException 
	 * @throws IllegalStateException 
	 * @throws DataLengthException 
	 */
	private byte[] decAES(byte[] input, byte[] keyBytes) throws Exception {
		byte[] ivBytes = new byte[AES_BLOCKSIZE];
		System.arraycopy(input, 0, ivBytes, 0, AES_BLOCKSIZE);
		byte[] stripped = new byte[input.length - AES_BLOCKSIZE];
		System.arraycopy(input, AES_BLOCKSIZE, stripped, 0, input.length - AES_BLOCKSIZE);

		KeyParameter keyParam = new KeyParameter(keyBytes);
		CipherParameters params = new ParametersWithIV(keyParam, ivBytes);

		BlockCipherPadding padding = new PKCS7Padding();
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding);
		cipher.reset();
		cipher.init(false, params);

		int len = 0;
		byte[] output = new byte[cipher.getOutputSize(stripped.length)];

		len = cipher.processBytes(stripped, 0, stripped.length, output, 0);
		len += cipher.doFinal(output, len);

		byte[] depadded = new byte[len];
		System.arraycopy(output, 0, depadded, 0, len);
		return depadded;
	}

	// /////////////////////////////////////////////////////////////
	// //////////////// PRIVATE KEY ENCRYPTION /////////////////////
	// /////////////////////////////////////////////////////////////

	/**
	 * Encryption using RSA - Wrapper for Message Objects Uses RSA Encryption or Hybrid (RSA+AES) encryption depending of message length Encoding:
	 * RSA-Encryption: |-- 1st Byte: Type 0x03 --|-- message --| Encoding: Hybrid-Encryption: |-- 1st Byte: Type 0x02 --|-- enc(symmKey, pk) --|--
	 * encSym(message, symmKey) --|
	 * 
	 * @throws CryptoException
	 */
	
	public Message encPK(Message message, EncryptionKey encryptKey) throws CryptoException {
		return encPK(message, encryptKey.getPublicKey());
	}
	
	public Message encPK(Message message, SigningKey signingKey) throws CryptoException {
		BigInteger exponent = signingKey.getPrivateKey().getPrivateExponent();
		BigInteger modulus = signingKey.getPrivateKey().getModulus();
		PublicKey pubKey;
		try {
			pubKey = new RSAPublicKeyImpl(modulus, exponent);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
		return encPK(message, pubKey);
	}
	
	private Message encPK(Message message, PublicKey pubKey) throws CryptoException {
		try {
			boolean hybrid = false;
			if (message.getByteLength() >= pkKeySize) {
				hybrid = true;
			} else {
				hybrid = false;
			}

			if (hybrid) {
				SymmetricKey symKeyObj = generateSymKey();
				byte[] encMessage = (encSym(message, symKeyObj)).getBytesWOTag();
				byte[] symKey = new byte[symKeyObj.getKey().getEncoded().length];
				System.arraycopy(symKeyObj.getKey().getEncoded(), 0, symKey, 0, symKeyObj.getKey().getEncoded().length);
				byte[] symKeyEnc = encRSA(symKey, pubKey);
				byte[] out = new byte[pkKeySize + encMessage.length];
				System.arraycopy(symKeyEnc, 0, out, 0, pkKeySize); // SymKey
				System.arraycopy(encMessage, 0, out, pkKeySize, encMessage.length); // symmetrical

				return Message.getMessageFromBytes(Message.TAG_ENCRYPTION_HYB, out);
			} else {
				byte[] enc = encRSA(message.getBytes(), pubKey);
				byte[] rawOut = new byte[enc.length];
				System.arraycopy(enc, 0, rawOut, 0, enc.length);
				return Message.getMessageFromBytes(Message.TAG_ENCRYPTION_PK, rawOut);
			}
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	/**
	 * Encryption using RSA
	 */
	private byte[] encRSA(byte[] in, java.security.PublicKey publicKey) {
		try {
			Cipher rsaCipher = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");
			rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			rsaCipher.update(in);
			return rsaCipher.doFinal();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	// /////////////////////////////////////////////////////////////
	// //////////////// PRIVATE KEY DECRYPTION /////////////////////
	// /////////////////////////////////////////////////////////////

	/**
	 * Decryption using RSA - Wrapper for Message objects Uses RSA Encryption or Hybrid (RSA+AES) encryption depending of message length Expected encoding:
	 * RSA-Encryption: |-- 1st Byte: Type 0x03 --|-- message --| Expected encoding: Hybrid-Encryption: |-- 1st Byte: Type 0x02 --|-- enc(symmKey, pk) --|--
	 * encSym(message, symmKey) --|
	 * 
	 * @throws CryptoException
	 */
	public Message decPK(Message message, DecryptionKey decKey) throws CryptoException {
		return decPK(message, decKey.getPrivateKey());
	}
	
	public Message decPK(Message message, VerificationKey veriKey) throws CryptoException {
		BigInteger exponent = veriKey.getPublicKey().getPublicExponent();
		BigInteger modulus =  veriKey.getPublicKey().getModulus();

		RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(modulus, exponent);
		KeyFactory keyFactory;
		PrivateKey pk;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			pk = keyFactory.generatePrivate(privKeySpec);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
		return decPK(message, pk);
	}
	
	private Message decPK(Message message, PrivateKey privateKey) throws CryptoException {
		try {
			byte[] realMessageRaw = message.getBytes();
			boolean hybrid = false;

			if (message.getTag() == Message.TAG_ENCRYPTION_HYB) {
				hybrid = true;
			}

			/////// HYBRID DECRYPTION ////////
			if (hybrid) {
				// Read encrypted key
				byte[] keyRaw = new byte[pkKeySize];
				System.arraycopy(realMessageRaw, 1, keyRaw, 0, pkKeySize);

				byte[] keyRawDec = null;
				keyRawDec = decRSA(keyRaw, privateKey);

				// Here we extrace the enc(message, symmKey)
				byte[] messageEncRaw = new byte[realMessageRaw.length - (1 + pkKeySize)];
				System.arraycopy(realMessageRaw, 1 + pkKeySize, messageEncRaw, 0, messageEncRaw.length);
				Message messageEnc = Message.getMessageFromBytes(Message.TAG_ENCRYPTION_HYB, messageEncRaw);

				if (keyRawDec.length != skKeySize) {
					throw new IllegalArgumentException("SymmetricKey not valid! Maybe wrong publicKey was used?");
				}
				SymmetricKey symKey = new SymmetricKey(new SecretKeySpec(keyRawDec, AES256_CBC_MODE));
				return decSym(messageEnc, symKey);
			} else {
			/////// NORMAL DECRYPTION ////////
				byte[] tmp = new byte[realMessageRaw.length - 1];
				System.arraycopy(realMessageRaw, 1, tmp, 0, tmp.length);

				byte[] out = decRSA(tmp, privateKey);
				return Message.getMessageFromBytes(Message.TAG_DUMMY, out);
			}
		} catch (Exception e) {
			throw new CryptoException(e);
		}

	}

	private byte[] decRSA(byte[] in, PrivateKey privateKey) throws CryptoException {
		try {
			Cipher rsaCipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
			rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
			rsaCipher.update(in);
			return rsaCipher.doFinal();
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

}
