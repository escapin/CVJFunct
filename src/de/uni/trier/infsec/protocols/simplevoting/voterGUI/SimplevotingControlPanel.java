package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import java.awt.EventQueue;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.util.ArrayList;
import java.util.Arrays;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.border.EmptyBorder;

import de.uni.trier.infsec.protocols.simplevoting.HTTPBulletinBoard;
import de.uni.trier.infsec.protocols.simplevoting.NetworkProxy;
import de.uni.trier.infsec.protocols.simplevoting.VoterStandalone;
import de.uni.trier.infsec.protocols.simplevoting.VotingServerStandalone;
import java.awt.Color;

public class SimplevotingControlPanel extends JFrame implements KeyListener, ActionListener {

	private static final long serialVersionUID = -5414028508877061099L;
	private JPanel contentPane;
	private JTextField txtPath;
	public String selectedFolder = ".";

	public Process proxyProcess = null;
	public Process serverProcess = null;
	public Process bulletinBoardProcess = null;

	JLabel lblServerStatus;
	JLabel lblProxyStatus;
	JLabel lblBulletinStatus;

	private JTextField txtProxyListenPort;
	private JTextField txtBBHttpPort;
	private JTextField txtClientServerAddress;
	private JTextField txtClientServerPort;
	private JTextField txtServerBBAddress;
	private JTextField txtServerBBPort;
	private JTextField txtProxyServerPort;
	private JTextField txtProxyServerAddress;
	private JTextField txtBBListenPort;

	private JComboBox<String> comboBox;
	private JSpinner cntFiles;

	private int proxyListenPort;
	private int bbHttpPort;
	private int clientServerPort;
	private int serverBBPort;
	private int proxyServerPort;
	private int bbListenPort;
	private int serverListenPort;

	private String clientServerAddress;
	private String proxyServerAddress;
	private String serverBBAddress;
	private JTextField txtServerListenPort;

	public static final String CMD_BROWSE = "BROWSE";
	public static final String CMD_START_SERVER = "START_SERVER";
	public static final String CMD_STOP_SERVER = "STOP_SERVER";
	public static final String CMD_START_PROXY = "START_PROXY";
	public static final String CMD_STOP_PROXY = "STOP_PROXY";
	public static final String CMD_START_BULLETIN = "START_BULLETIN";
	public static final String CMD_STOP_BULLETIN = "STOP_BULLETIN";
	public static final String CMD_REFRESH = "REFRESH";
	public static final String CMD_GENERATE = "GENERATE";
	public static final String CMD_START_CLIENT = "START_CLIENT";

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					SimplevotingControlPanel frame = new SimplevotingControlPanel();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public SimplevotingControlPanel() {
		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent e) {
				if (serverProcess != null)
					serverProcess.destroy();
				if (bulletinBoardProcess != null)
					bulletinBoardProcess.destroy();
				if (proxyProcess != null)
					proxyProcess.destroy();
			}
		});
		setResizable(false);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 474, 552);
		contentPane = new JPanel();
		contentPane.setBackground(Color.WHITE);
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		JButton btnStartServer = new JButton("Start");
		btnStartServer.addActionListener(this);

		txtPath = new JTextField();
		txtPath.setEditable(false);
		txtPath.setBounds(10, 23, 340, 20);
		contentPane.add(txtPath);
		txtPath.setColumns(10);

		txtProxyListenPort = new JTextField();
		txtProxyListenPort.setText("4242");
		txtProxyListenPort.setBounds(254, 210, 46, 20);
		contentPane.add(txtProxyListenPort);
		txtProxyListenPort.setColumns(10);

		txtBBHttpPort = new JTextField();
		txtBBHttpPort.setText("8888");
		txtBBHttpPort.setBounds(254, 359, 46, 20);
		contentPane.add(txtBBHttpPort);
		txtBBHttpPort.setColumns(10);

		txtClientServerAddress = new JTextField();
		txtClientServerAddress.setText("127.0.0.1");
		txtClientServerAddress.setBounds(254, 452, 86, 20);
		contentPane.add(txtClientServerAddress);
		txtClientServerAddress.setColumns(10);

		txtClientServerPort = new JTextField();
		txtClientServerPort.setText("4242");
		txtClientServerPort.setBounds(254, 426, 46, 20);
		contentPane.add(txtClientServerPort);
		txtClientServerPort.setColumns(10);

		txtServerBBAddress = new JTextField();
		txtServerBBAddress.setText("127.0.0.1");
		txtServerBBAddress.setBounds(254, 163, 86, 20);
		contentPane.add(txtServerBBAddress);
		txtServerBBAddress.setColumns(10);

		txtServerBBPort = new JTextField();
		txtServerBBPort.setText("4554");
		txtServerBBPort.setBounds(254, 105, 46, 20);
		contentPane.add(txtServerBBPort);
		txtServerBBPort.setColumns(10);

		txtProxyServerPort = new JTextField();
		txtProxyServerPort.setText("4043");
		txtProxyServerPort.setBounds(254, 241, 46, 20);
		contentPane.add(txtProxyServerPort);
		txtProxyServerPort.setColumns(10);

		txtProxyServerAddress = new JTextField();
		txtProxyServerAddress.setText("127.0.0.1");
		txtProxyServerAddress.setBounds(254, 268, 86, 20);
		contentPane.add(txtProxyServerAddress);
		txtProxyServerAddress.setColumns(10);

		txtBBListenPort = new JTextField();
		txtBBListenPort.setText("4554");
		txtBBListenPort.setBounds(254, 384, 46, 20);
		contentPane.add(txtBBListenPort);
		txtBBListenPort.setColumns(10);

		JButton btnStopServer = new JButton("Stop");
		btnStopServer.addActionListener(this);
		btnStopServer.setBounds(10, 162, 89, 23);
		btnStopServer.setActionCommand(CMD_STOP_SERVER);
		contentPane.add(btnStopServer);

		JButton btnStartProxy = new JButton("Start");
		btnStartProxy.addActionListener(this);
		btnStartProxy.setBounds(10, 240, 89, 23);
		btnStartProxy.setActionCommand(CMD_START_PROXY);
		contentPane.add(btnStartProxy);

		JButton btnStopProxy = new JButton("Stop");
		btnStopProxy.addActionListener(this);
		btnStopProxy.setBounds(10, 267, 89, 23);
		btnStopProxy.setActionCommand(CMD_STOP_PROXY);
		contentPane.add(btnStopProxy);

		JButton btnStartBulletinBoard = new JButton("Start");
		btnStartBulletinBoard.addActionListener(this);
		btnStartBulletinBoard.setBounds(10, 358, 89, 23);
		btnStartBulletinBoard.setActionCommand(CMD_START_BULLETIN);
		contentPane.add(btnStartBulletinBoard);

		JButton btnStopBulletinBoard = new JButton("Stop");
		btnStopBulletinBoard.addActionListener(this);
		btnStopBulletinBoard.setBounds(10, 383, 89, 23);
		btnStopBulletinBoard.setActionCommand(CMD_STOP_BULLETIN);
		contentPane.add(btnStopBulletinBoard);

		JButton btnStartClient = new JButton("Start");
		btnStartClient.addActionListener(this);
		btnStartClient.setActionCommand(CMD_START_CLIENT);
		btnStartClient.setBounds(10, 451, 89, 23);
		contentPane.add(btnStartClient);

		JButton btnBrowse = new JButton("Browse");
		btnBrowse.addActionListener(this);
		btnBrowse.setActionCommand(CMD_BROWSE);
		btnBrowse.setBounds(360, 22, 89, 23);
		contentPane.add(btnBrowse);

		JButton btnGenerateKeyfiles = new JButton("Generate Keyfiles");
		btnGenerateKeyfiles.addActionListener(this);
		btnGenerateKeyfiles.setBounds(271, 54, 178, 23);
		btnGenerateKeyfiles.setActionCommand(CMD_GENERATE);
		contentPane.add(btnGenerateKeyfiles);

		JButton btnRefresh = new JButton("Refresh");
		btnRefresh.addActionListener(this);
		btnRefresh.setBounds(377, 451, 72, 23);
		btnRefresh.setActionCommand(CMD_REFRESH);
		contentPane.add(btnRefresh);
		btnStartServer.setBounds(10, 133, 89, 23);
		btnStartServer.setActionCommand(CMD_START_SERVER);
		contentPane.add(btnStartServer);

		txtProxyListenPort.addKeyListener(this);
		txtBBHttpPort.addKeyListener(this);
		txtClientServerAddress.addKeyListener(this);
		txtClientServerPort.addKeyListener(this);
		txtServerBBAddress.addKeyListener(this);
		txtServerBBPort.addKeyListener(this);
		txtProxyServerPort.addKeyListener(this);
		txtProxyServerAddress.addKeyListener(this);
		txtBBListenPort.addKeyListener(this);

		JLabel lblVotingServer = new JLabel("Voting Server");
		lblVotingServer.setFont(new Font("Tahoma", Font.BOLD, 12));
		lblVotingServer.setBounds(10, 92, 116, 14);
		contentPane.add(lblVotingServer);

		JLabel lblVotingProxy = new JLabel("Voting Proxy");
		lblVotingProxy.setFont(new Font("Tahoma", Font.BOLD, 12));
		lblVotingProxy.setBounds(10, 199, 86, 14);
		contentPane.add(lblVotingProxy);

		JLabel lblBulletinBoard = new JLabel("Bulletin Board");
		lblBulletinBoard.setFont(new Font("Tahoma", Font.BOLD, 12));
		lblBulletinBoard.setBounds(10, 307, 116, 14);
		contentPane.add(lblBulletinBoard);

		lblServerStatus = new JLabel("offline");
		lblServerStatus.setBounds(10, 111, 46, 14);
		contentPane.add(lblServerStatus);

		lblProxyStatus = new JLabel("offline");
		lblProxyStatus.setBounds(10, 216, 46, 14);
		contentPane.add(lblProxyStatus);

		lblBulletinStatus = new JLabel("offline");
		lblBulletinStatus.setBounds(10, 332, 46, 14);
		contentPane.add(lblBulletinStatus);

		cntFiles = new JSpinner();
		cntFiles.setModel(new SpinnerNumberModel(new Integer(20), new Integer(0), null, new Integer(1)));
		cntFiles.setBounds(208, 57, 46, 20);
		contentPane.add(cntFiles);

		JLabel lblBulletinboardAddress = new JLabel("BulletinBoard Address");
		lblBulletinboardAddress.setBounds(136, 166, 116, 14);
		contentPane.add(lblBulletinboardAddress);

		JLabel lblPort = new JLabel("BulletinBoard Port");
		lblPort.setBounds(136, 108, 116, 14);
		contentPane.add(lblPort);

		JLabel lblExternalPort = new JLabel("External port");
		lblExternalPort.setBounds(136, 213, 118, 14);
		contentPane.add(lblExternalPort);

		JLabel lblVotingserverPort = new JLabel("VotingServer Port");
		lblVotingserverPort.setBounds(136, 244, 118, 14);
		contentPane.add(lblVotingserverPort);

		JLabel lblVotingserverAddress = new JLabel("VotingServer Address");
		lblVotingserverAddress.setBounds(136, 271, 118, 14);
		contentPane.add(lblVotingserverAddress);

		JLabel lblHttpPort = new JLabel("HTTP Port");
		lblHttpPort.setBounds(136, 362, 103, 14);
		contentPane.add(lblHttpPort);

		JLabel lblListenPort = new JLabel("Listen port");
		lblListenPort.setBounds(136, 387, 103, 14);
		contentPane.add(lblListenPort);

		comboBox = new JComboBox<String>();
		comboBox.setBounds(10, 483, 439, 23);
		contentPane.add(comboBox);

		txtServerListenPort = new JTextField();
		txtServerListenPort.setText("4043");
		txtServerListenPort.setBounds(254, 134, 46, 20);
		contentPane.add(txtServerListenPort);
		txtServerListenPort.setColumns(10);

		JLabel lblListenPort_1 = new JLabel("Listen Port");
		lblListenPort_1.setBounds(136, 137, 116, 14);
		contentPane.add(lblListenPort_1);

		JLabel lblPleaseChooseNumber = new JLabel("Choose number of Clients to prepare");
		lblPleaseChooseNumber.setBounds(10, 58, 188, 14);
		contentPane.add(lblPleaseChooseNumber);

		JLabel lblServerPort = new JLabel("Server Port");
		lblServerPort.setBounds(136, 429, 97, 14);
		contentPane.add(lblServerPort);

		JLabel lblServerAddress = new JLabel("Server Address");
		lblServerAddress.setBounds(136, 455, 97, 14);
		contentPane.add(lblServerAddress);

		JLabel lblNewLabel = new JLabel("Voting Client");
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 12));
		lblNewLabel.setBounds(10, 429, 97, 14);
		contentPane.add(lblNewLabel);
	}

	private void refreshVoterList() {
		File dir = new File(selectedFolder);
		File[] files = dir.listFiles(new FilenameFilter() {
			@Override
			public boolean accept(File dir, String name) {
				return (name.endsWith(".pri"));
			}
		});
		comboBox.removeAllItems();
		for (File f : files) {
			comboBox.addItem(f.getAbsolutePath());
		}
	}

	@Override
	public void keyPressed(KeyEvent e) {
	}

	@Override
	public void keyReleased(KeyEvent e) {
	}

	@Override
	public void keyTyped(KeyEvent e) {
		refreshValues();
	}

	public void refreshValues() {
		proxyListenPort = Integer.parseInt(txtProxyListenPort.getText());
		bbHttpPort = Integer.parseInt(txtBBHttpPort.getText());
		clientServerPort = Integer.parseInt(txtClientServerPort.getText());
		serverBBPort = Integer.parseInt(txtServerBBPort.getText());
		proxyServerPort = Integer.parseInt(txtProxyServerPort.getText());
		bbListenPort = Integer.parseInt(txtBBListenPort.getText());
		serverListenPort = Integer.parseInt(txtServerListenPort.getText());

		clientServerAddress = txtClientServerAddress.getText();
		serverBBAddress = txtServerBBAddress.getText();
		proxyServerAddress = txtProxyServerAddress.getText();
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		System.out.println(String.format("Action performed. Command: %s", event.getActionCommand()));
		refreshValues();

		if (event.getActionCommand().equalsIgnoreCase(CMD_GENERATE)) {
			try {
				PrepareAndRunServer.prepareFiles(selectedFolder, Integer.parseInt(cntFiles.getValue().toString()));
			} catch (Exception e) {
				e.printStackTrace();
			}
			refreshVoterList();
		} else if (event.getActionCommand().equalsIgnoreCase(CMD_REFRESH)) {
			refresh();
		} else if (event.getActionCommand().equalsIgnoreCase(CMD_START_BULLETIN)) {
			System.out.println(String.format("Starting BulletinBoard on port %d and HTTPPort %d", bbListenPort, bbHttpPort));
			bulletinBoardProcess = execJavaCommand(HTTPBulletinBoard.class.getName(), Integer.toString(bbListenPort), Integer.toString(bbHttpPort));
		} else if (event.getActionCommand().equalsIgnoreCase(CMD_START_PROXY)) {
			System.out.println(String.format("Starting Proxy on port %d with ServerAddress %s and ServerPort %d", proxyListenPort, proxyServerAddress,
					proxyServerPort));
			proxyProcess = execJavaCommand(NetworkProxy.class.getName(), Integer.toString(proxyListenPort), proxyServerAddress,
					Integer.toString(proxyServerPort));
		} else if (event.getActionCommand().equalsIgnoreCase(CMD_START_SERVER)) {
			System.out.println(String.format("Starting Server on port %d with BBAddress %s and BBPort %d", serverListenPort, serverBBAddress, serverBBPort));
			serverProcess = execJavaCommand(VotingServerStandalone.class.getName(), selectedFolder + File.separator + "clients.evo",
					Integer.toString(serverListenPort), serverBBAddress, Integer.toString(serverBBPort));
		} else if (event.getActionCommand().equalsIgnoreCase(CMD_START_CLIENT)) {
			System.out.println(String.format("Starting Client on ServerAddress %s, ServerPort %d,  Files %s and %s", clientServerAddress, clientServerPort,
					comboBox.getSelectedItem().toString().replaceAll("\\.pri", "\\.pub"), comboBox.getSelectedItem().toString()));
			execJavaCommand(VoterStandalone.class.getName(), comboBox.getSelectedItem().toString().replaceAll("\\.pri", "\\.pub"), comboBox.getSelectedItem()
					.toString(), clientServerAddress, Integer.toString(clientServerPort));
		} else if (event.getActionCommand().equalsIgnoreCase(CMD_STOP_BULLETIN)) {
			if (bulletinBoardProcess != null)
				bulletinBoardProcess.destroy();
		} else if (event.getActionCommand().equalsIgnoreCase(CMD_STOP_PROXY)) {
			if (proxyProcess != null)
				proxyProcess.destroy();
		} else if (event.getActionCommand().equalsIgnoreCase(CMD_STOP_SERVER)) {
			if (serverProcess != null)
				serverProcess.destroy();
		} else if (event.getActionCommand().equalsIgnoreCase(CMD_BROWSE)) {
			JFileChooser chooser = new JFileChooser(selectedFolder);
			chooser.setMultiSelectionEnabled(false);
			chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
			chooser.showOpenDialog(SimplevotingControlPanel.this);
			if (chooser.getSelectedFile() != null) {
				selectedFolder = chooser.getSelectedFile().getAbsolutePath();
				txtPath.setText(selectedFolder);
			}
			refreshVoterList();
		}
		refresh();
	}

	public Process execJavaCommand(String... command) {
		ArrayList<String> al = new ArrayList<>(Arrays.asList(command));
		al.add(0, System.getProperties().getProperty("java.class.path"));
		al.add(0, "-cp");
		al.add(0, "java");
		ProcessBuilder pb = new ProcessBuilder(al);
		File log = new File(System.getProperty("java.io.tmpdir") + File.separator + "evoting.log");
		pb.redirectErrorStream(true);
		pb.redirectOutput(Redirect.appendTo(log));
		try {
			return pb.start();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	public void refresh() {
		try {
			lblServerStatus.setText("offline");
			if (serverProcess != null)
				serverProcess.exitValue(); // throws exception in case not yet terminated
		} catch (Exception ex) {
			lblServerStatus.setText("online");
		}
		try {
			lblProxyStatus.setText("offline");
			if (proxyProcess != null)
				proxyProcess.exitValue(); // throws exception in case not yet terminated
		} catch (Exception ex) {
			lblProxyStatus.setText("online");
		}
		try {
			lblBulletinStatus.setText("offline");
			if (bulletinBoardProcess != null)
				bulletinBoardProcess.exitValue(); // throws exception in case not yet terminated
		} catch (Exception ex) {
			lblBulletinStatus.setText("online");
		}
	}
}