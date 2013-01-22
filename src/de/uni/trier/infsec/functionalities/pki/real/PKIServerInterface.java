package de.uni.trier.infsec.functionalities.pki.real;

import java.rmi.RemoteException;

public interface PKIServerInterface extends java.rmi.Remote {
	public SignedMessage register(int id, byte[] pubKey) throws RemoteException;
	public SignedMessage getPublicKey(int id) throws RemoteException;
	public void test() throws RemoteException;
}
