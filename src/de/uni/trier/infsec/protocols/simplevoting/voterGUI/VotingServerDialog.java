package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JFrame;

import de.uni.trier.infsec.protocols.simplevoting.VotingServerStandalone;
import javax.swing.JLabel;
import java.awt.Font;
import javax.swing.SwingConstants;

public class VotingServerDialog {

	private JFrame frmEvotingServerAdministration = null;
	private JLabel lblStatus = null;
	private VotingServerStandalone server = null;
	
	public VotingServerDialog(VotingServerStandalone server) {
		this.server = server;
		initialize();
	}
	
	private void initialize() {
		frmEvotingServerAdministration = new JFrame();
		frmEvotingServerAdministration.setTitle("eVoting Server Administration");
		frmEvotingServerAdministration.setBounds(100, 100, 346, 219);
		frmEvotingServerAdministration.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmEvotingServerAdministration.getContentPane().setLayout(null);
		
		JButton btnStartCountingPhase = new JButton("Count and publish");
		btnStartCountingPhase.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {					
					server.setPhase(VotingServerStandalone.PHASE_COUNT_AND_SUBMIT);
					lblStatus.setText("Votes counted and published");
					server.countAndPublish();
				} catch (IllegalStateException se) {
					new ErrorDialog(se.getMessage());
				}
			}
		}); 
		btnStartCountingPhase.setBounds(12, 146, 317, 25);
		frmEvotingServerAdministration.getContentPane().add(btnStartCountingPhase);
		
		JLabel lblNewLabel = new JLabel("Current Status");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setBounds(12, 12, 317, 15);
		frmEvotingServerAdministration.getContentPane().add(lblNewLabel);
		
		JButton btnStartCollectionPhase = new JButton("Start Ballot collection");
		btnStartCollectionPhase.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					server.setPhase(VotingServerStandalone.PHASE_COLLECT_BALLOT);
					lblStatus.setText("Collecting ballots");
				} catch (IllegalStateException se) {
					new ErrorDialog(se.getMessage());
				}
			}
		});
		btnStartCollectionPhase.setBounds(12, 109, 317, 25);
		frmEvotingServerAdministration.getContentPane().add(btnStartCollectionPhase);
		
		JButton btnStartRegistrationPhase = new JButton("Start Registration phase");
		btnStartRegistrationPhase.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					server.setPhase(VotingServerStandalone.PHASE_REGISTRATION);
					lblStatus.setText("Waiting for registrations");
				} catch (IllegalStateException se) {
					new ErrorDialog(se.getMessage());					
				}
			}
		});
		btnStartRegistrationPhase.setBounds(12, 72, 317, 25);
		frmEvotingServerAdministration.getContentPane().add(btnStartRegistrationPhase);
		
		lblStatus = new JLabel("offline");
		lblStatus.setHorizontalAlignment(SwingConstants.CENTER);
		lblStatus.setFont(new Font("Dialog", Font.BOLD, 16));
		lblStatus.setBounds(12, 39, 317, 15);
		frmEvotingServerAdministration.getContentPane().add(lblStatus);
	}
	
	public void start() {
		frmEvotingServerAdministration.setVisible(true);
		try {
			server.startServer();
		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}

}
