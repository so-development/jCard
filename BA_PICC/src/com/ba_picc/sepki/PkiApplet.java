package com.ba_picc.sepki;

import static com.ba_picc.sepki.ISO7816.SW_CLA_NOT_SUPPORTED;
import static com.ba_picc.sepki.ISO7816.SW_CONDITIONS_NOT_SATISFIED;
import static com.ba_picc.sepki.ISO7816.SW_INS_NOT_SUPPORTED;
import static com.ba_picc.sepki.ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
import static com.ba_picc.sepki.ISO7816.SW_SUCCESS;
import static com.ba_picc.sepki.ISO7816.SW_UNKNOWN;
import static com.ba_picc.sepki.ISO7816.SW_WRONG_LENGTH;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;

import Management.JCardTransportClass;
import android.content.Context;
import android.preference.PreferenceManager;
import android.security.KeyChain;
import core.Communication.JCard;
import core.Exceptions.ConnectionException;
import core.Exceptions.InvalidActionException;
import core.Exceptions.InvalidCAPDUException;
import core.Exceptions.InvalidRAPDUException;
import core.ISO7816_4.CAPDU;
import core.ISO7816_4.RAPDU;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;

/**
 * Borrowed of
 * https://github.com/nelenkov/virtual-pki-card/tree/master/se-emulator and
 * adapted for project. Class now uses jCard API to communicate with reader
 * 
 */

public class PkiApplet {

	private static final String PIN_KEY = "pin";
	private static final String KEY_ALIAS_KEY = "key_alias";

	// applet commands
	private final static byte PKI_APPLET_CLA = (byte) 0x80;
	private final static byte INS_VERIFY_PIN = (byte) 0x01;
	private final static byte INS_SIGN_DATA = (byte) 0x02;

	private Context ctx;
	private JCard jcard;

	private boolean authenticated = false;

	private volatile boolean isRunning = false;

	private Thread appletThread;

	public PkiApplet(Context ctx) {
		this.ctx = ctx;
	}

	public void start(final JCard jcard) throws IOException {
		this.jcard = jcard;

		Runnable r = new Runnable() {
			public void run() {
				try {
					CAPDU cmd;
					RAPDU response;

					cmd = (CAPDU) jcard
							.getLastReceivedData(LogState.APPLICATION_STARTED);
					if (!isInitialized()) {
						Log.addEntry(
								"Applet not initialized",
								LogType.WARNING,
								LogState.APPLICATION_STARTED,
								LogLevel.HIGH);

						response = new RAPDU(
								toBytes(SW_CONDITIONS_NOT_SATISFIED),
								LogState.APPLICATION_STARTED);
						jcard.sendRAPDU(
								response,
								LogState.APPLICATION_STARTED);
						resetState();
					}

					if (cmd.getCLA() != PKI_APPLET_CLA) {
						Log.addEntry(
								"Unsupported command class",
								LogType.ERROR,
								LogState.APPLICATION_STARTED,
								LogLevel.HIGH);

						response = new RAPDU(
								toBytes(SW_CLA_NOT_SUPPORTED),
								LogState.APPLICATION_STARTED);
						jcard.sendRAPDU(
								response,
								LogState.APPLICATION_STARTED);
						resetState();
					}

					if (cmd.getINS() != INS_VERIFY_PIN) {
						Log.addEntry(
								"Unsupported instruction",
								LogType.ERROR,
								LogState.APPLICATION_STARTED,
								LogLevel.HIGH);
						response = new RAPDU(
								toBytes(SW_INS_NOT_SUPPORTED),
								LogState.APPLICATION_STARTED);
						jcard.sendRAPDU(
								response,
								LogState.APPLICATION_STARTED);
						cmd = (CAPDU) jcard
								.getLastReceivedData(LogState.APPLICATION_STARTED);
					} else {
						if (cmd.getBytes().length < 5) {
							Log.addEntry(
									"Expecting command with data",
									LogType.ERROR,
									LogState.APPLICATION_STARTED,
									LogLevel.HIGH);

							response = new RAPDU(
									toBytes(SW_WRONG_LENGTH),
									LogState.APPLICATION_STARTED);
							jcard.sendRAPDU(
									response,
									LogState.APPLICATION_STARTED);
							resetState();
						} else {
							byte[] pinData = cmd.getData();
							String pin = new String(
									pinData, "ASCII");
							if (Crypto.checkPassword(
									getPin(), pin)) {
								Log.addEntry(
										"VERIFY PIN success",
										LogType.INFORMATION,
										LogState.APPLICATION_STARTED,
										LogLevel.HIGH);

								response = new RAPDU(
										toBytes(SW_SUCCESS),
										LogState.APPLICATION_STARTED);
								jcard.sendRAPDU(
										response,
										LogState.APPLICATION_STARTED);
								cmd = (CAPDU) jcard
										.getLastReceivedData(LogState.APPLICATION_STARTED);

								authenticated = true;
							} else {
								Log.addEntry(
										"Invalid PIN",
										LogType.ERROR,
										LogState.APPLICATION_STARTED,
										LogLevel.HIGH);

								response = new RAPDU(
										toBytes(SW_SECURITY_STATUS_NOT_SATISFIED),
										LogState.APPLICATION_STARTED);
								jcard.sendRAPDU(
										response,
										LogState.APPLICATION_STARTED);
								resetState();
							}
						}
					}

					if (cmd.getINS() != INS_SIGN_DATA) {
						Log.addEntry(
								"Unsupported instruction",
								LogType.ERROR,
								LogState.APPLICATION_STARTED,
								LogLevel.HIGH);

						response = new RAPDU(
								toBytes(SW_INS_NOT_SUPPORTED),
								LogState.APPLICATION_STARTED);
						jcard.sendRAPDU(
								response,
								LogState.APPLICATION_STARTED);
						resetState();
					} else {
						if (cmd.getBytes().length < 5) {
							Log.addEntry(
									"Expecting command with data",
									LogType.ERROR,
									LogState.APPLICATION_STARTED,
									LogLevel.HIGH);

							response = new RAPDU(
									toBytes(SW_WRONG_LENGTH),
									LogState.APPLICATION_STARTED);
							jcard.sendRAPDU(
									response,
									LogState.APPLICATION_STARTED);
							resetState();
						}
						if (!authenticated) {
							Log.addEntry(
									"Need to authenticate first",
									LogType.ERROR,
									LogState.APPLICATION_STARTED,
									LogLevel.HIGH);

							response = new RAPDU(
									toBytes(SW_SECURITY_STATUS_NOT_SATISFIED),
									LogState.APPLICATION_STARTED);
							jcard.sendRAPDU(
									response,
									LogState.APPLICATION_STARTED);
							resetState();
						}

						byte[] signedData = cmd.getData();
						try {
							Log.addEntry(
									"Sending signature",
									LogType.INFORMATION,
									LogState.APPLICATION_STARTED,
									LogLevel.HIGH);
							PrivateKey pk = KeyChain
									.getPrivateKey(ctx,
											getAlias());
							byte[] signature = Crypto.sign(
									pk, signedData);

							response = new RAPDU(
									signature,
									toBytes(SW_SUCCESS),
									LogState.APPLICATION_STARTED);
							jcard.sendRAPDU(
									response,
									LogState.APPLICATION_STARTED);

						} catch (Exception e) {
							Log.addEntry(
									"Error: "
											+ e.getMessage(),
									LogType.ERROR,
									LogState.APPLICATION_STARTED,
									LogLevel.HIGH);

							response = new RAPDU(
									toBytes(SW_UNKNOWN),
									LogState.APPLICATION_STARTED);
							jcard.sendRAPDU(
									response,
									LogState.APPLICATION_STARTED);
						}
					}
				} catch (InvalidActionException e) {
					resetState();
				} catch (ConnectionException e) {
					resetState();
				} catch (InvalidRAPDUException e) {
					resetState();
				} catch (InvalidCAPDUException e) {
					resetState();
				} catch (UnsupportedEncodingException e) {
					resetState();
				} catch (Exception e) {
					resetState();
				} finally {
					resetState();
				}

			}
		};

		appletThread = new Thread(r);
		appletThread.setName("PKI applet thread#"
				+ appletThread.getId());
		appletThread.start();
		isRunning = true;

		Log.addEntry("Started applet thread",
				LogType.INFORMATION,
				LogState.APPLICATION_STARTED, LogLevel.HIGH);
	}

	public boolean isRunning() {
		return isRunning;
	}

	public synchronized void stop() {
		Log.addEntry("stopping applet thread",
				LogType.INFORMATION,
				LogState.APPLICATION_STARTED, LogLevel.HIGH);
		if (appletThread != null) {
			appletThread.interrupt();
			Log.addEntry("applet thread running: "
					+ isRunning, LogType.INFORMATION,
					LogState.APPLICATION_STARTED,
					LogLevel.HIGH);
		}

		Log.addEntry("Resetting applet state",
				LogType.INFORMATION,
				LogState.APPLICATION_STARTED, LogLevel.HIGH);
		resetState();
	}

	public String getAlias() {
		return PreferenceManager
				.getDefaultSharedPreferences(ctx)
				.getString(KEY_ALIAS_KEY, null);
	}

	public void setAlias(String alias) {
		PreferenceManager.getDefaultSharedPreferences(ctx)
				.edit().putString(KEY_ALIAS_KEY, alias)
				.commit();
	}

	public String getPin() {
		return PreferenceManager
				.getDefaultSharedPreferences(ctx)
				.getString(PIN_KEY, null);
	}

	public void setPin(String pin) {
		String protectedPin = Crypto.protectPassword(pin);
		PreferenceManager.getDefaultSharedPreferences(ctx)
				.edit().putString(PIN_KEY, protectedPin)
				.commit();
	}

	private static byte[] toBytes(short s) {
		return new byte[] { (byte) ((s & 0xff00) >> 8),
				(byte) (s & 0xff) };
	}

	public boolean isInitialized() {
		return getAlias() != null && getPin() != null;
	}

	private void resetState() {
		try {
			Log.addEntry("Stopping applet thread",
					LogType.INFORMATION,
					LogState.APPLICATION_STARTED,
					LogLevel.HIGH);
			isRunning = false;
			authenticated = false;
			if (jcard != null) {
				jcard.closeConnection();
			}

		} catch (Exception e) {
		}
		JCardTransportClass.setJcard(null);
	}
}
