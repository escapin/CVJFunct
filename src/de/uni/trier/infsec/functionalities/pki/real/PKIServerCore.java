package de.uni.trier.infsec.functionalities.pki.real;

import java.io.File;

import org.tmatesoft.sqljet.core.SqlJetException;
import org.tmatesoft.sqljet.core.SqlJetTransactionMode;
import org.tmatesoft.sqljet.core.table.ISqlJetCursor;
import org.tmatesoft.sqljet.core.table.ISqlJetTable;
import org.tmatesoft.sqljet.core.table.SqlJetDb;

import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.utils.Utilities;

public class PKIServerCore implements PKIServerInterface {
	
	public static final String DEFAULT_DATABASE = System.getProperty("java.io.tmpdir") + File.separator + "evoting_server.db";
	private static final String DB_TABLE_NAME = "PKI";
	private static final String DB_COLUMN_NAME = "ENCRYPTOR";
	// Table PKI stores ID and corresponding Public Key in hex-representation
	private static final String DB_TABLE_CREATE = "CREATE TABLE PKI (ID TEXT NOT NULL PRIMARY KEY, ENCRYPTOR TEXT NOT NULL)";
	private static boolean dbInitialized = false;
	
	


	/**
	 * Registers the key and stores it into a local filebased database.
	 * True, if key was successfully stored,
	 * False, in case key is already registered or an error occured. 
	 */
	protected static boolean pki_register(int id, byte[] pubKey) {
		if (!dbInitialized) initDB();
		try {
			db.beginTransaction(SqlJetTransactionMode.WRITE);
			ISqlJetTable table = db.getTable(DB_TABLE_NAME);
			ISqlJetCursor cursor = table.lookup(null, id);
			if (cursor.first()) {
				echo("Public Key for id " + id + " is already registered!");
				return false;
			} else {
				echo("Public Key for id " + id + " is not registered!");				
			}
			
			table.insert(id, Utilities.byteArrayToHexString(pubKey));
			db.commit();
			
			return true;
		} catch (SqlJetException e) {
			e.printStackTrace();
			return false;
		}
	}

	/**
	 * Reads the public key from a local database and returns it.
	 * Returns null if no entry found. 
	 */
	protected static byte[] pki_getPublicKey(int id) {
		if (!dbInitialized) initDB();
		try {
			db.beginTransaction(SqlJetTransactionMode.READ_ONLY);
			ISqlJetTable table = db.getTable(DB_TABLE_NAME);
			ISqlJetCursor cursor = table.lookup(null, id);
			if (cursor.first()) {
				String sPubKey = cursor.getString(DB_COLUMN_NAME);
				byte[] pubKey  = Utilities.hexStringToByteArray(sPubKey);
				return pubKey;
			}
		} catch (SqlJetException e) {
			e.printStackTrace();
			return null;
		}
		return null;
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
				db.createTable(DB_TABLE_CREATE);
				db.commit();
			} else {
				db = SqlJetDb.open(dbFile, true);
			}
			dbInitialized = true;
		} catch (SqlJetException e) {
			e.printStackTrace();
		}
	}

	@Override
	public SignedMessage register(int id, byte[] pubKey) {
		if (!pki_register(id, pubKey)) return null;
		byte[] out = MessageTools.concatenate(MessageTools.intToByteArray(id), pubKey);
		return new SignedMessage(out, null);
	}

	@Override
	public SignedMessage getPublicKey(int id) {
		byte[] pubKey = pki_getPublicKey(id);
		byte[] out = MessageTools.concatenate(MessageTools.intToByteArray(id), pubKey);
		return new SignedMessage(out, null);
	}

	@Override
	public void test() {
		// TODO What is this method intended to do?
	}
	
	static void echo(String txt) {
		if (!Boolean.parseBoolean(System.getProperty("DEBUG"))) return;
		System.out.println("[" + PKIServerCore.class.getSimpleName() + "] " + txt);
	}
}
