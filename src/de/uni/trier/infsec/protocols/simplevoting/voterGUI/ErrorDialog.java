package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import java.awt.Color;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.SwingConstants;

public class ErrorDialog extends JDialog {

	private static final long serialVersionUID = -8453284667893128562L;

	public ErrorDialog(String message) {
		getContentPane().setBackground(Color.WHITE);
		setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
		setTitle("eVoting: Error");
		setResizable(false);
		setModalityType(ModalityType.APPLICATION_MODAL);
		setBounds(100, 100, 345, 143);
		getContentPane().setLayout(null);
		{
			JLabel lblError = new JLabel("There was an error:");
			lblError.setBounds(10, 11, 319, 19);
			getContentPane().add(lblError);
			lblError.setFont(new Font("Dialog", Font.BOLD, 14));
		}
		{
			JLabel lblMessage = new JLabel("Message");
			lblMessage.setBounds(10, 34, 319, 20);
			getContentPane().add(lblMessage);
			lblMessage.setVerticalAlignment(SwingConstants.TOP);
			lblMessage.setHorizontalAlignment(SwingConstants.LEFT);
			lblMessage.setText(message);
		}
		{
			JButton okButton = new JButton("OK");
			okButton.setBounds(10, 81, 319, 23);
			getContentPane().add(okButton);
			okButton.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					dispose();
				}
			});
			okButton.setActionCommand("OK");
			getRootPane().setDefaultButton(okButton);
		}
		setVisible(true);
	}

}
