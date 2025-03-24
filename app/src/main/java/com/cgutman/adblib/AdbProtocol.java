package com.cgutman.adblib;


import android.util.Log;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;


/**
 * This class provides useful functions and fields for ADB protocol details.
 * @author Cameron Gutman
 */
public class AdbProtocol {
	private static final String TAG = "AdbProtocol";

	/** The length of the ADB message header */
	public static final int ADB_HEADER_LENGTH = 24;
	
	public static final int CMD_SYNC = 0x434e5953;
	
	/** CNXN is the connect message. No messages (except AUTH) 
	 * are valid before this message is received. */
	public static final int CMD_CNXN = 0x4e584e43;
	
	/** The current version of the ADB protocol */
	public static final int CONNECT_VERSION = 0x01000000;

	// Stream-based TLS protocol version
	public static final int CONNECT_VERSION_STLS_MIN = 0x01000000;
	public static final int CONNECT_VERSION_STLS = 0x01000000;
	
	/** The maximum data payload supported by the ADB implementation */
	public static final int CONNECT_MAXDATA = 4096;
	
	/** The payload sent with the connect message */
	public static byte[] CONNECT_PAYLOAD;
	static {
		try {
			CONNECT_PAYLOAD = "host::\0".getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {}
	}

	public static final String kFeatureShell2 = "shell_v2";
	public static final String kFeatureCmd = "cmd";
	public static final String kFeatureStat2 = "stat_v2";
	public static final String kFeatureLs2 = "ls_v2";
	public static final String kFeatureLibusb = "libusb";		//-
	public static final String kFeaturePushSync = "push_sync";	//-
	public static final String kFeatureApex = "apex";
	public static final String kFeatureFixedPushMkdir = "fixed_push_mkdir";
	public static final String kFeatureAbb = "abb";
	public static final String kFeatureFixedPushSymlinkTimestamp = "fixed_push_symlink_timestamp";
	public static final String kFeatureAbbExec = "abb_exec";
	public static final String kFeatureRemountShell = "remount_shell";
	public static final String kFeatureTrackApp = "track_app";
	public static final String kFeatureSendRecv2 = "sendrecv_v2";
	public static final String kFeatureSendRecv2Brotli = "sendrecv_v2_brotli";
	public static final String kFeatureSendRecv2LZ4 = "sendrecv_v2_lz4";
	public static final String kFeatureSendRecv2Zstd = "sendrecv_v2_zstd";
	public static final String kFeatureSendRecv2DryRunSend = "sendrecv_v2_dry_run_send";
	public static final String kFeatureDelayedAck = "delayed_ack";	//-
	// TODO(joshuaduong): Bump to v2 when openscreen discovery is enabled by default
	public static final String kFeatureOpenscreenMdns = "openscreen_mdns";
	public static final String kFeatureDeviceTrackerProtoFormat = "devicetracker_proto_format";
	public static final String kFeatureDevRaw = "devraw";
	public static final String kFeatureAppInfo = "app_info";  // Add information to track-app (package name, ...)
	public static final String kFeatureServerStatus = "server_status";  // Ability to output server status

	public static byte[] CONNECT_PAYLOAD_STLS;
	static {
		try {
			CONNECT_PAYLOAD_STLS = ("host::features="
					+ "," + kFeatureShell2
					+ "," + kFeatureCmd
					+ "," + kFeatureStat2
					+ "," + kFeatureLs2
					+ "," + kFeatureApex
					+ "," + kFeatureFixedPushMkdir
					+ "," + kFeatureAbb
					+ "," + kFeatureFixedPushSymlinkTimestamp
					+ "," + kFeatureAbbExec
					+ "," + kFeatureRemountShell
					+ "," + kFeatureTrackApp
					+ "," + kFeatureSendRecv2
					+ "," + kFeatureSendRecv2Brotli
					+ "," + kFeatureSendRecv2LZ4
					+ "," + kFeatureSendRecv2Zstd
					+ "," + kFeatureSendRecv2DryRunSend
					+ "," + kFeatureOpenscreenMdns
					+ "," + kFeatureDeviceTrackerProtoFormat
					+ "," + kFeatureDevRaw
					+ "," + kFeatureAppInfo
					+ "," + kFeatureServerStatus
			).getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {}
	}
	
	/** AUTH is the authentication message. It is part of the
	 * RSA public key authentication added in Android 4.2.2. */
	public static final int CMD_AUTH = 0x48545541;
	
	/** This authentication type represents a SHA1 hash to sign */
	public static final int AUTH_TYPE_TOKEN = 1;
	
	/** This authentication type represents the signed SHA1 hash */
	public static final int AUTH_TYPE_SIGNATURE = 2;
	
	/** This authentication type represents a RSA public key */
	public static final int AUTH_TYPE_RSA_PUBLIC = 3;
	
	/** OPEN is the open stream message. It is sent to open
	 * a new stream on the target device. */
	public static final int CMD_OPEN = 0x4e45504f;

	/** STLS is the open stream message. It is sent to open
	 * a new stream on the target device. */
	public static final int CMD_STLS = 0x534C5453;

	/** OKAY is a success message. It is sent when a write is
	 * processed successfully. */
	public static final int CMD_OKAY = 0x59414b4f;
	
	/** CLSE is the close stream message. It it sent to close an
	 * existing stream on the target device. */
	public static final int CMD_CLSE = 0x45534c43;
	
	/** WRTE is the write stream message. It is sent with a payload
	 * that is the data to write to the stream. */
	public static final int CMD_WRTE = 0x45545257;
	
	/**
	 * This function performs a checksum on the ADB payload data.
	 * @param payload Payload to checksum
	 * @return The checksum of the payload
	 */
	private static int getPayloadChecksum(byte[] payload)
	{
		int checksum = 0;
		
		for (byte b : payload)
		{
			/* We have to manually "unsign" these bytes because Java sucks */
			if (b >= 0)
				checksum += b;
			else
				checksum += b+256;
		}
		
		return checksum;
	}
	
	/**
	 * This function validate the ADB message by checking
	 * its command, magic, and payload checksum.
	 * @param msg ADB message to validate
	 * @return True if the message was valid, false otherwise
	 */
	public static boolean validateMessage(AdbMessage msg)
	{
		showLog("validateMessage");
		/* Magic is cmd ^ 0xFFFFFFFF */
		if (msg.command != (msg.magic ^ 0xFFFFFFFF))
			return false;
		
		if (msg.payloadLength != 0)
		{
			if (getPayloadChecksum(msg.payload) != msg.checksum)
				return false;
		}

		showLog("validateMessage, true");
		return true;
	}
	
	/**
	 * This function generates an ADB message given the fields.
	 * @param cmd Command identifier
	 * @param arg0 First argument
	 * @param arg1 Second argument
	 * @param payload Data payload
	 * @return Byte array containing the message
	 */
	public static byte[] generateMessage(int cmd, int arg0, int arg1, byte[] payload)
	{
		/* struct message {
         * 		unsigned command;       // command identifier constant
         * 		unsigned arg0;          // first argument
         * 		unsigned arg1;          // second argument
         * 		unsigned data_length;   // length of payload (0 is allowed)
         * 		unsigned data_check;    // checksum of data payload
         * 		unsigned magic;         // command ^ 0xffffffff
         * };
         */
		showLog("generateMessage::"
				+ "cmd: " + commandToString(cmd)
				+ "arg0: " + arg0
				+ "arg1: " + arg1
				+ "pl: " + (payload !=null ? Arrays.toString(payload) : null));

		ByteBuffer message;
		
		if (payload != null)
		{
			message = ByteBuffer.allocate(ADB_HEADER_LENGTH + payload.length).order(ByteOrder.LITTLE_ENDIAN);
		}
		else
		{
			message = ByteBuffer.allocate(ADB_HEADER_LENGTH).order(ByteOrder.LITTLE_ENDIAN);
		}
		
		message.putInt(cmd);
		message.putInt(arg0);
		message.putInt(arg1);
		
		if (payload != null)
		{
			message.putInt(payload.length);
			message.putInt(getPayloadChecksum(payload));
		}
		else
		{
			message.putInt(0);
			message.putInt(0);
		}
		
		message.putInt(cmd ^ 0xFFFFFFFF);
		
		if (payload != null)
		{
			message.put(payload);
		}
		
		return message.array();
	}
	
	/**
	 * Generates a connect message with default parameters.
	 * @return Byte array containing the message
	 */
	public static byte[] generateConnect()
	{
		showLog("generateConnect");
		return generateMessage(CMD_CNXN, CONNECT_VERSION, CONNECT_MAXDATA, CONNECT_PAYLOAD_STLS);
	}

	/**
	 * Generates a connect message with default parameters.
	 * @return Byte array containing the message
	 */
	public static byte[] generateSTLS()
	{
		showLog("generateConnect");
		return generateMessage(CMD_STLS, CONNECT_VERSION_STLS, 0, null);
	}
	
	/**
	 * Generates an auth message with the specified type and payload.
	 * @param type Authentication type (see AUTH_TYPE_* constants)
	 * @param data The payload for the message
	 * @return Byte array containing the message
	 */
	public static byte[] generateAuth(int type, byte[] data)
	{
		showLog("generateAuth, type: " + type + ", data: " + Arrays.toString(data));
		return generateMessage(CMD_AUTH, type, 0, data);
	}
	
	/**
	 * Generates an open stream message with the specified local ID and destination.
	 * @param localId A unique local ID identifying the stream
	 * @param dest The destination of the stream on the target
	 * @return Byte array containing the message
	 * @throws UnsupportedEncodingException If the destination cannot be encoded to UTF-8
	 */
	public static byte[] generateOpen(int localId, String dest) throws UnsupportedEncodingException
	{
		showLog("generateOpen, localId: " + localId + ", dest: " + dest);
		ByteBuffer bbuf = ByteBuffer.allocate(dest.length() + 1);
		bbuf.put(dest.getBytes("UTF-8"));
		bbuf.put((byte)0);
		return generateMessage(CMD_OPEN, localId, 0, bbuf.array());
	}
	
	/**
	 * Generates a write stream message with the specified IDs and payload. 
	 * @param localId The unique local ID of the stream
	 * @param remoteId The unique remote ID of the stream
	 * @param data The data to provide as the write payload
	 * @return Byte array containing the message
	 */
	public static byte[] generateWrite(int localId, int remoteId, byte[] data)
	{
		showLog("generateWrite, localId: " + localId + ", remoteId: " + remoteId
				+ ", data: " + Arrays.toString(data));
		return generateMessage(CMD_WRTE, localId, remoteId, data);
	}
	
	/**
	 * Generates a close stream message with the specified IDs.
	 * @param localId The unique local ID of the stream
	 * @param remoteId The unique remote ID of the stream
	 * @return Byte array containing the message
	 */
	public static byte[] generateClose(int localId, int remoteId)
	{
		showLog("generateClose, localId: " + localId + ", remoteId: " + remoteId);
		return generateMessage(CMD_CLSE, localId, remoteId, null);
	}
	
	/**
	 * Generates an okay message with the specified IDs.
	 * @param localId The unique local ID of the stream
	 * @param remoteId The unique remote ID of the stream
	 * @return Byte array containing the message
	 */
	public static byte[] generateReady(int localId, int remoteId)
	{
		showLog("generateReady, localId: " + localId + ", remoteId: " + remoteId);
		return generateMessage(CMD_OKAY, localId, remoteId, null);
	}
	
	/**
	 * This class provides an abstraction for the ADB message format.
	 * @author Cameron Gutman
	 */
	final static class AdbMessage {
		/** The command field of the message */
		public int command;
		/** The arg0 field of the message */
		public int arg0;
		/** The arg1 field of the message */
		public int arg1;
		/** The payload length field of the message */
		public int payloadLength;
		/** The checksum field of the message */
		public int checksum;
		/** The magic field of the message */
		public int magic;
		/** The payload of the message */
		public byte[] payload;
		
		/**
		 * Read and parse an ADB message from the supplied input stream.
		 * This message is NOT validated.
		 * @param in InputStream object to read data from
		 * @return An AdbMessage object represented the message read
		 * @throws IOException If the stream fails while reading
		 */
		public static AdbMessage parseAdbMessage(InputStream in) throws IOException
		{
			showLog("parseAdbMessage");
			AdbMessage msg = new AdbMessage();
			ByteBuffer packet = ByteBuffer.allocate(ADB_HEADER_LENGTH).order(ByteOrder.LITTLE_ENDIAN);
			
			/* Read the header first */
			int dataRead = 0;
			do
			{
				int bytesRead = in.read(packet.array(), dataRead, 24 - dataRead);
				
				if (bytesRead < 0)
					throw new IOException("Stream closed");
				else
					dataRead += bytesRead;
			}
			while (dataRead < ADB_HEADER_LENGTH);
			
			/* Pull out header fields */
			msg.command = packet.getInt();
			msg.arg0 = packet.getInt();
			msg.arg1 = packet.getInt();
			msg.payloadLength = packet.getInt();
			msg.checksum = packet.getInt();
			msg.magic = packet.getInt();
			
			/* If there's a payload supplied, read that too */
			if (msg.payloadLength != 0)
			{
				msg.payload = new byte[msg.payloadLength];
				
				dataRead = 0;
				do
				{
					int bytesRead = in.read(msg.payload, dataRead, msg.payloadLength - dataRead);
					
					if (bytesRead < 0)
						throw new IOException("Stream closed");
					else
						dataRead += bytesRead;
				}
				while (dataRead < msg.payloadLength);
			}

			showLog("parseAdbMessage, " + msg.toString());
			return msg;
		}

		@NonNull
		@Override
		public String toString() {
			return "Message:: "
					+ "cmd: " + commandToString(command)
					+ ", arg0: " + arg0
					+ ", arg1: " + arg1
					+ ", pLen: " + payloadLength
					+ ", pl: " + (payload !=null ? Arrays.toString(payload) : null);
		}
	}

	public static String commandToString(int cmd) {
		switch (cmd) {
			case CMD_SYNC:
				return "A_SYNC";
			case CMD_CNXN:
				return "A_CNXN";
			case CMD_OPEN:
				return "A_OPEN";
			case CMD_OKAY:
				return "A_OKAY";
			case CMD_CLSE:
				return "A_CLSE";
			case CMD_WRTE:
				return "A_WRTE";
			case CMD_AUTH:
				return "A_AUTH";
			case CMD_STLS:
				return "A_STLS";
			default:
				return "UNKNOWN (" + "cmd: " +cmd + ")";
		}
	}
	private static void showLog(String log) {
		Log.e(Utils.IS_DEBUG ? "pankaj_" + TAG : TAG, log);
	}
}
