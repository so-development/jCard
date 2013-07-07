package com.ba_pcd;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import core.Communication.JCard;
import core.ISO7816_4.CAPDU;
import core.ISO7816_4.RAPDU;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;
import core.Management.AppData;
import core.Support.HelperClass;

/**
 * Borrowed of
 * https://github.com/nelenkov/virtual-pki-card/tree/master/se-emulator and
 * adapted for project. Class now uses jCard API to communicate with reader
 * 
 */
public class SEPKIClient implements
		core.Application.IPCDApplication {

	private static final short SW_SUCCESS = (short) 0x9000;

	private final static byte PKI_APPLET_CLA = (byte) 0x80;
	private final static byte INS_VERIFY_PIN = (byte) 0x01;
	private final static byte INS_SIGN = (byte) 0x02;

	private static byte[] readFile(String filename)
			throws Exception {
		File f = new File(filename);
		byte[] result = new byte[(int) f.length()];
		FileInputStream in = new FileInputStream(f);
		try {
			in.read(result);

			return result;
		} finally {
			in.close();
		}
	}

	private static void checkSW(RAPDU response) {

		if (!HelperClass.toHexString(response.getSW())
				.equals(HelperClass
						.toHexString(toBytes(SW_SUCCESS)))) {
			Log.addEntry("Received error. Exiting.",
					LogType.ERROR,
					LogState.APPLICATION_STARTED,
					LogLevel.HIGH);
			throw new RuntimeException(
					"Received error. Exiting.");
		}
	}

	@Override
	public void start(JCard jcard, AppData appData) {
		try {
			try {
				if (appData.getData("pin") == null
						|| appData.getData("cert") == null) {
					throw new RuntimeException(
							"You need to add data to your application! (ID: \"pin\" + ID:\"cert\" (certificate path))");
				}
				String pin = appData.getData("pin");
				CAPDU cmd = new CAPDU(PKI_APPLET_CLA,
						INS_VERIFY_PIN, (byte) 0x00,
						(byte) 0x00, pin.getBytes("ASCII"),
						LogState.APPLICATION_STARTED);
				jcard.sendCAPDU(cmd,
						LogState.APPLICATION_STARTED);
				RAPDU response = (RAPDU) jcard
						.getLastReceivedData(LogState.APPLICATION_STARTED);
				checkSW(response);

				byte[] signedData = "sign me!"
						.getBytes("ASCII");
				cmd = new CAPDU(PKI_APPLET_CLA, INS_SIGN,
						(byte) 0x00, (byte) 0x00,
						signedData,
						LogState.APPLICATION_STARTED);

				jcard.sendCAPDU(cmd,
						LogState.APPLICATION_STARTED);
				response = (RAPDU) jcard
						.getLastReceivedData(LogState.APPLICATION_STARTED);
				checkSW(response);

				byte[] signature = response.getData();
				Log.addEntry("Got signature from card: "
						+ toHex(signature),
						LogType.INFORMATION,
						LogState.APPLICATION_STARTED,
						LogLevel.HIGH);

				String certPath = appData.getData("cert")
						.trim();
				Log.addEntry(
						"Will use certificate from "
								+ certPath
								+ " to verify signature",
						LogType.INFORMATION,
						LogState.APPLICATION_STARTED,
						LogLevel.HIGH);

				byte[] certBlob = readFile(certPath);
				CertificateFactory cf = CertificateFactory
						.getInstance("X509");
				X509Certificate cert = (X509Certificate) cf
						.generateCertificate(new ByteArrayInputStream(
								certBlob));
				Log.addEntry("Issuer: "
						+ cert.getIssuerDN().getName(),
						LogType.INFORMATION,
						LogState.APPLICATION_STARTED,
						LogLevel.HIGH);

				Log.addEntry("Subject: "
						+ cert.getSubjectDN().getName(),
						LogType.INFORMATION,
						LogState.APPLICATION_STARTED,
						LogLevel.HIGH);
				Log.addEntry(
						"Not Before: "
								+ cert.getNotBefore(),
						LogType.INFORMATION,
						LogState.APPLICATION_STARTED,
						LogLevel.HIGH);
				Log.addEntry(
						"Not After: " + cert.getNotAfter(),
						LogType.INFORMATION,
						LogState.APPLICATION_STARTED,
						LogLevel.HIGH);

				Signature s = Signature
						.getInstance("SHA1withRSA");
				s.initVerify(cert);
				s.update(signedData);
				boolean valid = s.verify(signature);
				Log.addEntry(
						"Signature is valid: " + valid,
						LogType.INFORMATION,
						LogState.APPLICATION_STARTED,
						LogLevel.HIGH);

			} finally {
				try {
					jcard.closeConnection();
				} catch (Exception e) {
				}
			}

		} catch (Exception e) {
			Log.addEntry("Error: " + e.getMessage(),
					LogType.ERROR,
					LogState.APPLICATION_STARTED,
					LogLevel.HIGH);
		}

	}

	public static String toHex(byte[] bytes) {
		StringBuilder buff = new StringBuilder();
		for (byte b : bytes) {
			buff.append(String.format("%02X", b));
		}

		return buff.toString();
	}

	private static byte[] toBytes(short s) {
		return new byte[] { (byte) ((s & 0xff00) >> 8),
				(byte) (s & 0xff) };
	}
}
