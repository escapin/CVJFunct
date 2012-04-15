package de.uni.trier.infsec.protocols.simplevoting;

import org.apache.pivot.beans.BXMLSerializer;
import org.apache.pivot.collections.Map;
import org.apache.pivot.wtk.Application;
import org.apache.pivot.wtk.DesktopApplicationContext;
import org.apache.pivot.wtk.Display;

import de.uni.trier.infsec.protocols.simplevoting.voterGUI.VotingWindow;

public class VoterStandalone implements Application {
	private VotingWindow window = null;

	@Override
	public void resume() throws Exception {
	}

	@Override
	public boolean shutdown(boolean arg0) throws Exception {
		if (window != null) {
			window.close();
		}
		return false;
	}

	@Override
	public void startup(Display arg0, Map<String, String> arg1) throws Exception {
		BXMLSerializer xmlser = new BXMLSerializer();
		window = (VotingWindow) xmlser.readObject(VotingWindow.class, "VoterGUI.xml");
		window.open(arg0);
	}

	@Override
	public void suspend() throws Exception {
	}

	public static void main(String[] args) {
		DesktopApplicationContext.main(VoterStandalone.class, args);
	}

}
