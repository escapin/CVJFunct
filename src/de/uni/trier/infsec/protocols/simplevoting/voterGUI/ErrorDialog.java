package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

public class ErrorDialog extends JDialog {

	private static final long serialVersionUID = -8453284667893128562L;
	private final JPanel contentPanel = new JPanel();

	public ErrorDialog(String message) {
		setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
		setTitle("eVoting Error");
		setResizable(false);
		setModalityType(ModalityType.APPLICATION_MODAL);
		setBounds(100, 100, 361, 178);
		getContentPane().setLayout(new BorderLayout());
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		contentPanel.setLayout(new BorderLayout(0, 0));
		{
			JLabel lblError = new JLabel("There was an error:");
			lblError.setFont(new Font("Dialog", Font.BOLD, 14));
			contentPanel.add(lblError, BorderLayout.NORTH);
		}
		{
			JLabel lblMessage = new JLabel("Message");
			contentPanel.add(lblMessage, BorderLayout.CENTER);
			lblMessage.setText(message);
		}
		{
			JPanel buttonPane = new JPanel();
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			buttonPane.setLayout(new BorderLayout(0, 0));
			{
				JButton okButton = new JButton("OK");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						dispose();
					}
				});
				okButton.setActionCommand("OK");
				buttonPane.add(okButton);
				getRootPane().setDefaultButton(okButton);
			}
		}
		setVisible(true);
	}

}
