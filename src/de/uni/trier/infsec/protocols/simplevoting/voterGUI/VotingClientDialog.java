package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import java.awt.Color;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import javax.swing.border.LineBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import de.uni.trier.infsec.protocols.simplevoting.VoterStandalone;
import de.uni.trier.infsec.protocols.simplevoting.VotingServerStandalone;
import de.uni.trier.infsec.utils.Utilities;

public class VotingClientDialog {

	private JFrame frmEvotingClient;
	private VoterStandalone handler = null;
	private JList lstChoices = null;
	private JButton btnRegister = null;
	private JButton btnVoteNow = null;
	private JLabel lblTheCredential = null;
	private JLabel lblChoice = null;
	private JLabel lblCurrentstatus  = null;
	private JLabel lblPrivateKey = null;
	private JLabel lblPublicKey = null;
	
	private byte choice = 0x00;
	
	/**
	 * Create the application.
	 */
	public VotingClientDialog(VoterStandalone handler) {
		this.handler = handler;
		initialize();
	}

	
	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmEvotingClient = new JFrame();
		frmEvotingClient.setTitle("eVoting  -  Client");
		frmEvotingClient.setResizable(false);
		frmEvotingClient.getContentPane().setBackground(Color.WHITE);
		frmEvotingClient.setBounds(100, 100, 523, 551);
		frmEvotingClient.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmEvotingClient.getContentPane().setLayout(null);
		
		JPanel pnlStatus = new JPanel();
		pnlStatus.setBackground(Color.WHITE);
		pnlStatus.setBorder(new LineBorder(new Color(0, 0, 0), 2));
		pnlStatus.setBounds(22, 12, 480, 244);
		frmEvotingClient.getContentPane().add(pnlStatus);
		pnlStatus.setLayout(null);
		
		JLabel lblCredential = new JLabel("Your encrypted credential");
		lblCredential.setBounds(12, 144, 456, 15);
		pnlStatus.add(lblCredential);
		
		lblTheCredential = new JLabel("- unregistered -");
		lblTheCredential.setBounds(12, 171, 456, 15);
		pnlStatus.add(lblTheCredential);
		
		lblPrivateKey = new JLabel("PrivateKey");
		lblPrivateKey.setBounds(12, 221, 456, 15);
		pnlStatus.add(lblPrivateKey);
		lblPrivateKey.setText("Using private key from file " + handler.privateKeyPath);
		
		lblPublicKey = new JLabel("PublicKey");
		lblPublicKey.setBounds(12, 198, 456, 15);
		pnlStatus.add(lblPublicKey);
		lblPublicKey.setText("Using public key from file " + handler.publicKeyPath);
		
		JLabel lblStatus = new JLabel("Status:");
		lblStatus.setBounds(12, 13, 56, 15);
		pnlStatus.add(lblStatus);
		lblStatus.setVerticalAlignment(SwingConstants.BOTTOM);
		lblStatus.setFont(new Font("Dialog", Font.BOLD, 14));
		
		btnRegister = new JButton("Register");
		btnRegister.setEnabled(!handler.isRegistered());
		btnRegister.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					String response = handler.clickRegister();
					
					lblTheCredential.setText(response);
					btnRegister.setEnabled(!handler.isRegistered());
					btnVoteNow.setEnabled(handler.isRegistered());
					lstChoices.setEnabled(handler.isRegistered());
					lblCurrentstatus.setText(handler.isRegistered()?"Registered":"Unregistered");
				} catch (IllegalStateException s) {
					s.printStackTrace();
					new ErrorDialog(s.getMessage());
				} catch (Exception ee) {
					ee.printStackTrace();
					new ErrorDialog(ee.getMessage());
				}
			}
		});
		btnRegister.setBounds(12, 96, 456, 25);
		pnlStatus.add(btnRegister);
		
		
		lblCurrentstatus = new JLabel("currentStatus");
		lblCurrentstatus.setVerticalAlignment(SwingConstants.TOP);
		lblCurrentstatus.setBounds(81, 12, 387, 73);
		lblCurrentstatus.setText(handler.isRegistered()?"Registered":"Unregistered");
		pnlStatus.add(lblCurrentstatus);
		
		JPanel pnlChoices = new JPanel();
		pnlChoices.setBackground(Color.WHITE);
		pnlChoices.setBounds(0, 268, 521, 237);
		frmEvotingClient.getContentPane().add(pnlChoices);
		pnlChoices.setLayout(null);
		
		lstChoices = new JList(VotingServerStandalone.votes);
		lstChoices.addListSelectionListener(new ListSelectionListener() {
			public void valueChanged(ListSelectionEvent e) {
				choice = Utilities.hexStringToByteArray(lstChoices.getSelectedValue().toString())[0];
				lblChoice.setText(lstChoices.getSelectedValue().toString());
			}
		});
		lstChoices.setEnabled(handler.isRegistered());
		lstChoices.setBorder(new LineBorder(new Color(0, 0, 0), 2));
		lstChoices.setBounds(22, 39, 184, 186);
		pnlChoices.add(lstChoices);
		
		btnVoteNow = new JButton("Vote now");
		btnVoteNow.setEnabled(handler.isRegistered());
		btnVoteNow.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					handler.clickVote(choice);
				} catch (IllegalStateException s) {
					s.printStackTrace();
					new ErrorDialog(s.getMessage());
				} catch (Exception ee) {
					ee.printStackTrace();
					new ErrorDialog(ee.getMessage());
				}
			}
		});
		btnVoteNow.setBounds(310, 200, 191, 25);
		pnlChoices.add(btnVoteNow);
		
		JPanel pnlSelectedVote = new JPanel();
		pnlSelectedVote.setBackground(Color.WHITE);
		pnlSelectedVote.setBorder(new LineBorder(new Color(255, 0, 0), 3));
		pnlSelectedVote.setBounds(310, 12, 191, 176);
		pnlChoices.add(pnlSelectedVote);
		pnlSelectedVote.setLayout(null);
		
		lblChoice = new JLabel("- none -");
		lblChoice.setHorizontalAlignment(SwingConstants.CENTER);
		lblChoice.setFont(new Font("Dialog", Font.BOLD, 22));
		lblChoice.setBounds(12, 39, 167, 125);
		pnlSelectedVote.add(lblChoice);
		
		JLabel lblCurrentVote = new JLabel("Selected Vote");
		lblCurrentVote.setHorizontalAlignment(SwingConstants.CENTER);
		lblCurrentVote.setBounds(12, 12, 167, 25);
		pnlSelectedVote.add(lblCurrentVote);
		
		JLabel lblPleaseChooseYour = new JLabel("Please choose your vote:");
		lblPleaseChooseYour.setBounds(22, 12, 184, 15);
		pnlChoices.add(lblPleaseChooseYour);
	}


	public void showWindow() {
		this.frmEvotingClient.setVisible(true);
	}
}
