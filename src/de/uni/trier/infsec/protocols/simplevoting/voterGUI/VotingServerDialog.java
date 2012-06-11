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
import java.awt.Color;

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
		frmEvotingServerAdministration.getContentPane().setBackground(Color.WHITE);
		frmEvotingServerAdministration.setTitle("eVoting Server Administration");
		frmEvotingServerAdministration.setBounds(100, 100, 368, 232);
		frmEvotingServerAdministration.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmEvotingServerAdministration.getContentPane().setLayout(null);
		
		JLabel lblNewLabel = new JLabel("Current Status");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setBounds(12, 12, 330, 15);
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
		
		lblStatus = new JLabel("offline");
		lblStatus.setHorizontalAlignment(SwingConstants.CENTER);
		lblStatus.setFont(new Font("Dialog", Font.BOLD, 16));
		lblStatus.setBounds(12, 51, 330, 15);
		frmEvotingServerAdministration.getContentPane().add(lblStatus);
		btnStartCountingPhase.setBounds(12, 158, 330, 25);
		frmEvotingServerAdministration.getContentPane().add(btnStartCountingPhase);
		btnStartCollectionPhase.setBounds(12, 122, 330, 25);
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
		btnStartRegistrationPhase.setBounds(12, 86, 330, 25);
		frmEvotingServerAdministration.getContentPane().add(btnStartRegistrationPhase);
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
