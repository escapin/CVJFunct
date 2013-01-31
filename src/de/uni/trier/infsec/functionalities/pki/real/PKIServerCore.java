package de.uni.trier.infsec.functionalities.pki.real;

import java.io.File;

import org.tmatesoft.sqljet.core.SqlJetException;
import org.tmatesoft.sqljet.core.SqlJetTransactionMode;
import org.tmatesoft.sqljet.core.table.ISqlJetCursor;
import org.tmatesoft.sqljet.core.table.ISqlJetTable;
import org.tmatesoft.sqljet.core.table.SqlJetDb;

import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.Utilities;

public class PKIServerCore implements PKIServerInterface {
	
	public static final String DEFAULT_DATABASE = System.getProperty("java.io.tmpdir") + File.separator + "evoting_server.db";
	private static final String DB_TABLE_NAME_PKE = "PKI_ENC";
	private static final String DB_TABLE_NAME_SIG = "PKI_SIG";
	private static final String DB_COLUMN_NAME = "KEY";
	// Table PKI stores ID and corresponding Public Key in hex-representation
	private static final String DB_TABLE_CREATE_PKE = "CREATE TABLE " + DB_TABLE_NAME_PKE + " (ID TEXT NOT NULL PRIMARY KEY, " + DB_COLUMN_NAME + " TEXT NOT NULL)";
	private static final String DB_TABLE_CREATE_SIG = "CREATE TABLE " + DB_TABLE_NAME_SIG + " (ID TEXT NOT NULL PRIMARY KEY, " + DB_COLUMN_NAME + " TEXT NOT NULL)";
	private static boolean dbInitialized = false;
	
	
	
	@Override
	public void register(int id, byte[] pubKey) throws PKIError, NetworkError {
		pki_register(id, pubKey);
	}

	@Override
	public byte[] getPublicKey(int id) throws PKIError, NetworkError {
		return pki_getPublicKey(id);
	}

	@Override
	public void registerVerificationKey(int id, byte[] verKey) throws PKIError, NetworkError {
		registerVerificationKey(id, verKey);
	}

	@Override
	public byte[] getVerificationKey(int id) throws PKIError, NetworkError {
		return pki_getVerificationKey(id);
	}
	


	/**
	 * Registers the key and stores it into a local filebased database.
	 * True, if key was successfully stored,
	 * False, in case key is already registered or an error occured. 
	 */
	protected static void pki_register(int id, byte[] pubKey) throws PKIError, NetworkError {
		if (!dbInitialized) initDB();
		try {
			db.beginTransaction(SqlJetTransactionMode.WRITE);
			ISqlJetTable table = db.getTable(DB_TABLE_NAME_PKE);
			ISqlJetCursor cursor = table.lookup(null, id);
			if (cursor.first())	throw new PKIError(); // ID has been claimed
			
			table.insert(id, Utilities.byteArrayToHexString(pubKey));
			db.commit();
		} catch (SqlJetException e) {
			e.printStackTrace();
			throw new NetworkError(); // Something went wrong 
		}
	}

	/**
	 * Reads the public key from a local database and returns it.
	 * Returns null if no entry found. 
	 */
	protected static byte[] pki_getPublicKey(int id) throws PKIError, NetworkError {
		if (!dbInitialized) initDB();
		try {
			db.beginTransaction(SqlJetTransactionMode.READ_ONLY);
			ISqlJetTable table = db.getTable(DB_TABLE_NAME_PKE);
			ISqlJetCursor cursor = table.lookup(null, id);
			if (cursor.first()) {
				String sPubKey = cursor.getString(DB_COLUMN_NAME);
				byte[] pubKey  = Utilities.hexStringToByteArray(sPubKey);
				return pubKey;
			} else {
				throw new PKIError(); // ID not registered
			}
		} catch (SqlJetException e) {
			e.printStackTrace();
			throw new NetworkError(); // Something went wrong 
		}
	}
	
	/**
	 * Registers the key and stores it into a local filebased database.
	 * True, if key was successfully stored,
	 * False, in case key is already registered or an error occured. 
	 */
	protected static void pki_register_verification(int id, byte[] verificationKey) throws PKIError, NetworkError {
		if (!dbInitialized) initDB();
		try {
			db.beginTransaction(SqlJetTransactionMode.WRITE);
			ISqlJetTable table = db.getTable(DB_TABLE_NAME_SIG);
			ISqlJetCursor cursor = table.lookup(null, id);
			if (cursor.first()) throw new PKIError(); // ID has been claimed!
			
			table.insert(id, Utilities.byteArrayToHexString(verificationKey));
			db.commit();
		} catch (SqlJetException e) {
			e.printStackTrace();
			throw new NetworkError(); // Something went wrong 
		}
	}
	

	/**
	 * Reads the public key from a local database and returns it.
	 * Returns null if no entry found. 
	 */
	protected static byte[] pki_getVerificationKey(int id) throws PKIError, NetworkError {
		if (!dbInitialized) initDB();
		try {
			db.beginTransaction(SqlJetTransactionMode.READ_ONLY);
			ISqlJetTable table = db.getTable(DB_TABLE_NAME_SIG);
			ISqlJetCursor cursor = table.lookup(null, id);
			if (cursor.first()) {
				String sPubKey = cursor.getString(DB_COLUMN_NAME);
				byte[] pubKey  = Utilities.hexStringToByteArray(sPubKey);
				return pubKey;
			} else {
				throw new PKIError();
			}
		} catch (SqlJetException e) {
			e.printStackTrace();
			throw new NetworkError(); // Something went wrong 
		}
	}
	
	/// Implementation ///
	// We store the public keys in the SQLite DB (located in system temp directory)

	private static SqlJetDb db = null;
	private static void initDB() {
		try {
			File dbFile = new File(DEFAULT_DATABASE);
			if (!dbFile.exists()) {
				// We need to init a completely new Database
				db = SqlJetDb.open(dbFile, true);
				db.createTable(DB_TABLE_CREATE_PKE);
				db.createTable(DB_TABLE_CREATE_SIG);
				db.commit();
			} else {
				db = SqlJetDb.open(dbFile, true);
			}
			dbInitialized = true;
		} catch (SqlJetException e) {
			e.printStackTrace();
		}
	}

}
