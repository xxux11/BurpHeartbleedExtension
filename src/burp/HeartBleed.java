package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.StringWriter;

import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import org.python.core.PyString;
import org.python.core.PySystemState;
import org.python.util.PythonInterpreter;

/**
 * Heartbleed extension for burp suite.
 * @author Ashkan Jahanbakhsh
 *
 */

public class HeartBleed implements IMenuItemHandler, ITab, ActionListener {
	private IBurpExtenderCallbacks callbacks;
	private JPanel main; 
	private JPanel menu;
	private JTabbedPane tPane;
	private JComboBox<String> tabs;
	private final String TAB_NAME = "Heartbleed";
	private final int DEFAULT_PORT = 443;
	
	public HeartBleed(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName("Burp heartbleed extension");
		main = new JPanel(new BorderLayout());
		menu = new JPanel();
		menu.setPreferredSize(new Dimension(0, 500));
		tPane = new JTabbedPane();
		main.add(menu, BorderLayout.LINE_START);
		main.add(tPane, BorderLayout.CENTER);
		callbacks.customizeUiComponent(main);
		tabs = new JComboBox<String>();
		callbacks.addSuiteTab(HeartBleed.this);
	}

	@Override
	public void menuItemClicked(String arg0, final IHttpRequestResponse[] arg1) {
		String inpPort = JOptionPane.showInputDialog("Enter port number for " + arg1[0].getHost());
		int portNumber = DEFAULT_PORT;
		boolean parsable = true;
		try{
			portNumber = Integer.parseInt(inpPort);
		}catch(NumberFormatException e){
			parsable = false;
		}
		if(!parsable){
			portNumber = DEFAULT_PORT;
		}
		final int port = portNumber;
		try {
			if (arg1[0].getHost() != null) {

				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						prepareSslTest("Trying to connect to server: " + arg1[0].getHost() + ":" + port, arg1[0].getHost(), port);
					}
				});
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * Create a tab in burp send and start the test in a separate thread.
	 * @param value
	 * @param host
	 * @param port
	 */

	private void prepareSslTest(String value, final String host, final int port) {
		final JTextArea serverTab = new JTextArea(5, 30);
		serverTab.setEditable(false);
		serverTab.setText(value);
		JScrollPane scrollWindow = new JScrollPane(serverTab);
		scrollWindow.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scrollWindow.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		scrollWindow.setPreferredSize(tPane.getSize());
		serverTab.setBounds(tPane.getBounds());
		tabs.addItem(host);
		tPane.addTab(host, scrollWindow);
		tPane.setTabComponentAt(tPane.getTabCount() - 1,new Tab(tPane, this));

		Thread thread = new Thread() {
			public void run() {
				serverTab.append("\n\n");
				final String output = makeItBleed(host, port + "");
				serverTab.append(output);
			}
		};
		thread.start();
		

	}

	@Override
	public String getTabCaption() {
		return TAB_NAME;
	}

	@Override
	public Component getUiComponent() {
		return main;
	}

	/**
	 * Remove tab.
	 * @param index
	 */
	public void RemoveTab(int index) {
		String name = tPane.getTitleAt(index);
		tabs.removeItem(name);
		tPane.remove(index);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
	}

	/**
	 * Call python script by jython.
	 * @param host
	 * @param port
	 * @return
	 */
	private String makeItBleed(String host, String port) {
		String scriptname = "ssltest.py";
		PySystemState state = new PySystemState();
		state.argv.append(new PyString(host));
		state.argv.append(new PyString("-p " + port));
		PythonInterpreter python = new PythonInterpreter(null, state);
		StringWriter out = new StringWriter();
		python.setOut(out);
		python.execfile(scriptname);
		String outputStr = out.toString();
		return outputStr;
	}

}
