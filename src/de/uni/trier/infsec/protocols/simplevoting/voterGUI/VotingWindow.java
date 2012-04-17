package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import java.net.URL;

import org.apache.pivot.beans.Bindable;
import org.apache.pivot.collections.ArrayList;
import org.apache.pivot.collections.Map;
import org.apache.pivot.collections.Sequence;
import org.apache.pivot.util.Resources;
import org.apache.pivot.wtk.Button;
import org.apache.pivot.wtk.ButtonPressListener;
import org.apache.pivot.wtk.Label;
import org.apache.pivot.wtk.ListView;
import org.apache.pivot.wtk.ListViewSelectionListener;
import org.apache.pivot.wtk.PushButton;
import org.apache.pivot.wtk.Span;
import org.apache.pivot.wtk.TextInput;
import org.apache.pivot.wtk.Window;

import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Decryptor;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Encryptor;
import de.uni.trier.infsec.lib.network.Network;
import de.uni.trier.infsec.protocols.simplevoting.Voter;

public class VotingWindow extends Window implements Bindable,
		ButtonPressListener, ListViewSelectionListener {

	PushButton btnConnect = null;
	PushButton btnSubmit = null;
	ListView list = null;
	Label vote = null;
	Label status = null;
	TextInput pubKey = null;
	TextInput privKey = null;
	TextInput credent = null;
	
	public enum Votes {  // TODO: What do votes look like? single Byte?
		Candidate1, Candidate2, Candidate3
	}


	@Override
	public void initialize(Map<String, Object> namespace, URL location,
			Resources resources) {
		btnConnect = (PushButton) namespace.get("btnConnect");
		btnConnect.getButtonPressListeners().add(this);
		
		btnSubmit = (PushButton) namespace.get("btnSubmit");
		btnSubmit.getButtonPressListeners().add(this);

		vote = (Label) namespace.get("currentVote");
		status = (Label) namespace.get("status");

		pubKey = (TextInput) namespace.get("publickey");
		privKey = (TextInput) namespace.get("privatekey");
		credent = (TextInput) namespace.get("credential");

		list = (ListView) namespace.get("voteList");
		list.getListViewSelectionListeners().add(this);
		list.setListData(new ArrayList<Votes>(Votes.values()));
	}

	@Override
	public void buttonPressed(Button button) {
		
		if (button.equals(btnConnect)) {
			status.setText("Connecting");
			if (Network.connectToServer(Network.DEFAULT_SERVER, Network.DEFAULT_PORT)) {				
				status.setText("Connected to server");
			} else {
				status.setText("Could not connect to server");
			}
		} else if (button.equals(btnSubmit)) {
			// TODO How to handle key and credential distribution? Enter manually? Ask server for credential by button?
			byte[] publicKey = hexStringToByteArray(pubKey.getText());
			byte[] privateKey = hexStringToByteArray(privKey.getText());
			byte[] credential = hexStringToByteArray(credent.getText());
			byte vote = list.getSelectedItem().toString().getBytes()[0];
			
			Decryptor d = new Decryptor();
			Encryptor e = d.getEncryptor();
			// TODO: Decryptor.setPrivateKey etc
			Encryptor se = new Decryptor().getEncryptor();
			
			
			Voter voter = new Voter(d, se);
			voter.setCredential(credential);
			try {
				Network.networkOut( voter.makeBallot(vote) );
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}
	}

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
					.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	@Override
	public void selectedItemChanged(ListView arg0, Object arg1) {
		vote.setText(list.getSelectedItem().toString());
	}

	@Override
	public void selectedRangeAdded(ListView arg0, int arg1, int arg2) {
	}

	@Override
	public void selectedRangeRemoved(ListView arg0, int arg1, int arg2) {
	}

	@Override
	public void selectedRangesChanged(ListView arg0, Sequence<Span> arg1) {
	}

}
