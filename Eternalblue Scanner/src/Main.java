import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;

public class Main {

	public static void main(String[] args) {
		if (args.length == 0)
			System.out.println("scanner.jar <ip>");
		else
			check(args[0], 445);
	}

	private static String generate_smb_proto_payload(String[] listA, String[] listB, String[] listC) {
		String[] hexdata = new String[listA.length + listB.length + listC.length];

		System.arraycopy(listA, 0, hexdata, 0, listA.length);
		System.arraycopy(listB, 0, hexdata, listA.length, listB.length);
		System.arraycopy(listC, 0, hexdata, listB.length + listA.length, listC.length);

		return String.join("", hexdata);
	}

	private static String calculate_doublepulsar_xor_key(int s) {
		int x;
		x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)));
		x = x & 0xffffffff; // this line was added just to truncate to 32 bits
		return String.valueOf(x);
	}

	private static String negotiate_proto_request() {
		String[] netbios = { "\u0000", // 'Message_Type'
				"\u0000\u0000\u0054" // 'Length'
		};

		String[] smb_header = { "\u00FF\u0053\u004D\u0042", // 'server_component': .SMB
				"\u0072", // 'smb_command':Negotiate Protocol
				"\u0000\u0000\u0000\u0000", // 'nt_status'
				"\u0018", // 'flags'
				"\u0001\u0028", // 'flags2'
				"\u0000\u0000", // 'process_id_high'
				"\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000", // 'signature'
				"\u0000\u0000", // 'reserved'
				"\u0000\u0000", // 'tree_id'
				"\u002F\u004B", // 'process_id'
				"\u0000\u0000", // 'user_id'
				"\u00C5\u005E" // 'multiplex_id'
		};

		String[] negotiate_proto_request = { "\u0000", // 'word_count'
				"\u0031\u0000", // 'byte_count'

				// Requested Dialects
				"\u0002", // 'dialet_buffer_format'
				"\u004C\u0041\u004E\u004D\u0041\u004E\u0031\u002E\u0030\u0000", // 'dialet_name':LANMAN1 .0

				"\u0002", // 'dialet_buffer_format'
				"\u004C\u004D\u0031\u002E\u0032\u0058\u0030\u0030\u0032\u0000", // 'dialet_name':LM1 .2 X002

				"\u0002", // 'dialet_buffer_format'
				"\u004E\u0054\u0020\u004C\u0041\u004E\u004D\u0041\u004E\u0020\u0031\u002E\u0030\u0000", // 'dialet_name3':NT
																										// LANMAN 1.0

				"\u0002", // 'dialet_buffer_format'
				"\u004E\u0054\u0020\u004C\u004D\u0020\u0030\u002E\u0031\u0032\u0000" // 'dialet_name4':NT LM 0.12
		};

		return generate_smb_proto_payload(netbios, smb_header, negotiate_proto_request);

	}

	private static String session_setup_andx_request() {
		String[] netbios = { "\u0000", // 'Message_Type'
				"\u0000\u0000\u0063" // 'Length'
		};

		String[] smb_header = { "\u00FF\u0053\u004D\u0042", // 'server_component': .SMB
				"\u0073", // 'smb_command':Session Setup AndX
				"\u0000\u0000\u0000\u0000", // 'nt_status'
				"\u0018", // 'flags'
				"\u0001\u0020", // 'flags2'
				"\u0000\u0000", // 'process_id_high'
				"\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000", // 'signature'
				"\u0000\u0000", // 'reserved'
				"\u0000\u0000", // 'tree_id'
				"\u002F\u004B", // 'process_id'
				"\u0000\u0000", // 'user_id'
				"\u00C5\u005E" // 'multiplex_id'
		};

		String[] session_setup_andx_request = { "\r", // \u000D // Word Count
				"\u00FF", // AndXCommand: No further command
				"\u0000", // Reserved
				"\u0000\u0000", // AndXOffset
				"\u00DF\u00FF", // Max Buffer
				"\u0002\u0000", // Max Mpx Count
				"\u0001\u0000", // VC Number
				"\u0000\u0000\u0000\u0000", // Session Key
				"\u0000\u0000", // ANSI Password Length
				"\u0000\u0000", // Unicode Password Length
				"\u0000\u0000\u0000\u0000", // Reserved
				"\u0040\u0000\u0000\u0000", // Capabilities
				"\u0026\u0000", // Byte Count
				"\u0000", // Account
				"\u002e\u0000", // Primary Domain
				"\u0057\u0069\u006e\u0064\u006f\u0077\u0073\u0020\u0032\u0030\u0030\u0030\u0020\u0032\u0031\u0039\u0035\u0000", // Native
																																// OS:
																																// Windows
																																// 2000
																																// 2195
				"\u0057\u0069\u006e\u0064\u006f\u0077\u0073\u0020\u0032\u0030\u0030\u0030\u0020\u0035\u002e\u0030\u0000", // Native
																															// OS:
																															// Windows
																															// 2000
																															// 5.0
		};

		return generate_smb_proto_payload(netbios, smb_header, session_setup_andx_request);
	}

	private static String tree_connect_andx_request(String ip, String userid) {
		String[] netbios = { "\u0000", // 'Message_Type'
				"\u0000\u0000\u0047" // 'Length'
		};
		String[] smb_header = { "\u00FF\u0053\u004D\u0042", // 'server_component': .SMB
				"\u0075", // 'smb_command':Session Setup AndX
				"\u0000\u0000\u0000\u0000", // 'nt_status'
				"\u0018", // 'flags'
				"\u0001\u0020", // 'flags2'
				"\u0000\u0000", // 'process_id_high'
				"\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000", // 'signature'
				"\u0000\u0000", // 'reserved'
				"\u0000\u0000", // 'tree_id'
				"\u002F\u004B", // 'process_id'
				userid, // 'user_id'
				"\u00C5\u005E" // 'multiplex_id'
		};
		String ipc = "\\\\" + ip + "\\IPC$\u0000";

		String[] tree_connect_andx_request = { "\u0004", // Word Count
				"\u00FF", // AndXCommand: No further commands
				"\u0000", // Reserved
				"\u0000\u0000", // AndXOffset
				"\u0000\u0000", // Flags
				"\u0001\u0000", // Password Length
				"\u001A\u0000", // Byte Count
				"\u0000", // Password
				ipc, // \\u00xx.xxx.xxx.xxx\IPC$
				"\u003f\u003f\u003f\u003f\u003f\u0000" // Service
		};
		int len = String.join("", smb_header).length() + String.join("", tree_connect_andx_request).length();
		netbios[1] = "\u0000" + "\u0000" + (char) len;
		return generate_smb_proto_payload(netbios, smb_header, tree_connect_andx_request);

	}

	private static String peeknamedpipe_request(String treeid, String processid, String userid, String multiplex_id) {
		String[] netbios = { "\u0000", // 'Message_Type'
				"\u0000\u0000\u004a" // 'Length'
		};

		String[] smb_header = { "\u00FF\u0053\u004D\u0042", // 'server_component': .SMB
				"\u0025", // 'smb_command': Trans2
				"\u0000\u0000\u0000\u0000", // 'nt_status'
				"\u0018", // 'flags'
				"\u0001\u0028", // 'flags2'
				"\u0000\u0000", // 'process_id_high'
				"\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000", // 'signature'
				"\u0000\u0000", // 'reserved'
				treeid, processid, userid, multiplex_id };

		String[] tran_request = { "\u0010", // Word Count
				"\u0000\u0000", // Total Parameter Count
				"\u0000\u0000", // Total Data Count
				"\u00ff\u00ff", // Max Parameter Count
				"\u00ff\u00ff", // Max Data Count
				"\u0000", // Max Setup Count
				"\u0000", // Reserved
				"\u0000\u0000", // Flags
				"\u0000\u0000\u0000\u0000", // Timeout: Return immediately
				"\u0000\u0000", // Reversed
				"\u0000\u0000", // Parameter Count
				"\u004a\u0000", // Parameter Offset
				"\u0000\u0000", // Data Count
				"\u004a\u0000", // Data Offset
				"\u0002", // Setup Count
				"\u0000", // Reversed
				"\u0023\u0000", // SMB Pipe Protocol: Function: PeekNamedPipe (0x0023)
				"\u0000\u0000", // SMB Pipe Protocol: FID
				"\u0007\u0000", "\\\u0050\u0049\u0050\u0045\\\u0000" // \PIPE\
		};

		return generate_smb_proto_payload(netbios, smb_header, tran_request);
	}

	private static String trans2_request(String treeid, String processid, String userid, String multiplex_id) {
		String[] netbios = { "\u0000", // 'Message_Type'
				"\u0000\u0000\u004f" // 'Length'
		};

		String[] smb_header = { "\u00FF\u0053\u004D\u0042", // 'server_component': .SMB
				"\u0032", // 'smb_command': Trans2
				"\u0000\u0000\u0000\u0000", // 'nt_status'
				"\u0018", // 'flags'
				"\u0007\u00c0", // 'flags2'
				"\u0000\u0000", // 'process_id_high'
				"\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000", // 'signature'
				"\u0000\u0000", // 'reserved'
				treeid, processid, userid, multiplex_id };

		String[] trans2_request = { "\u000f", // Word Count
				"\u000c\u0000", // Total Parameter Count
				"\u0000\u0000", // Total Data Count
				"\u0001\u0000", // Max Parameter Count
				"\u0000\u0000", // Max Data Count
				"\u0000", // Max Setup Count
				"\u0000", // Reserved
				"\u0000\u0000", // Flags
				"\u00a6\u00d9\u00a4\u0000", // Timeout: 3 hours, 3.622 seconds
				"\u0000\u0000", // Reversed
				"\u000c\u0000", // Parameter Count
				"\u0042\u0000", // Parameter Offset
				"\u0000\u0000", // Data Count
				"\u004e\u0000", // Data Offset
				"\u0001", // Setup Count
				"\u0000", // Reserved
				"\u000e\u0000", // subcommand: SESSION_SETUP
				"\u0000\u0000", // Byte Count
				"\u000c\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000" };

		return generate_smb_proto_payload(netbios, smb_header, trans2_request);

	}

	private static void check(String ip, int port) {
		String tcp_response = "";
		try {
			System.out.println("\n----ETERNALBLUE SCANNER----\n");
			Socket s = new Socket(ip, port);
			OutputStream out = s.getOutputStream();

			out.write(negotiate_proto_request().getBytes());
			out.flush();
			response(s);

			out.write(session_setup_andx_request().getBytes());
			out.flush();
			tcp_response = response(s);

			String smb_header = tcp_response.substring(4, 36);
			String user_id = tcp_response.substring(32, 34);
			String session_setup_andx_response = tcp_response.substring(36);
			String native_os = session_setup_andx_response.substring(9).split("\u0000")[0];

			out.write(tree_connect_andx_request(ip, user_id).getBytes());
			out.flush();
			tcp_response = response(s);

			smb_header = tcp_response.substring(4, 36);

			String tree_id = smb_header.substring(24, 26);
			String process_id = smb_header.substring(26, 28);
			user_id = smb_header.substring(28, 30);
			String multiplex_id = smb_header.substring(30, 32);

			out.write(peeknamedpipe_request(tree_id, process_id, user_id, multiplex_id).getBytes());
			out.flush();
			tcp_response = response(s);

			smb_header = tcp_response.substring(4, 36);
			String nt_status = smb_header.substring(5, 9);

			System.out.println("OS: " + native_os);

			if (nt_status.equals("\u0005\u0002\u0000\u00c0")) {
				System.out.println("Host is likely VULNERABLE to MS17-010!");
				out.write(trans2_request(tree_id, process_id, user_id, multiplex_id).getBytes());
				out.flush();
				tcp_response = response(s);

				smb_header = tcp_response.substring(4, 36);
				multiplex_id = smb_header.substring(30, 32);
				String signature = smb_header.substring(15, 23);
				if (multiplex_id.equals("81")) {
					String key = calculate_doublepulsar_xor_key(Integer.valueOf(signature));
					System.out.println("Host is likely INFECTED with DoublePulsar! - XOR Key: " + key);
				}
			}

			else if (nt_status.equals("\u0008\u0000\u0000\u00c0") || nt_status.equals('\u0022' + "\u0000\u0000\u00c0"))
				System.out.println("Host does NOT appear vulnerable");

			else
				System.out.println("Unable to detect if this host is vulnerable");

			out.close();
			s.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private static String response(Socket s) throws IOException {
		String data;
		InputStream input = s.getInputStream();
		InputStreamReader reader = new InputStreamReader(input);
		data = "";
		int i = 0;
		data += (char) reader.read();
		data += (char) reader.read();
		data += (char) reader.read();
		int len = reader.read();
		data += (char) len;
		while (i < len) {
			data += (char) reader.read();
			i++;
		}
		return data;
	}

}
