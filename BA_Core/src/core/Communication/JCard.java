package core.Communication;

import core.Communication.Connection.IConnection;
import core.Exceptions.ConnectionException;
import core.Exceptions.InvalidActionException;
import core.Exceptions.InvalidCAPDUException;
import core.Exceptions.InvalidRAPDUException;
import core.Exceptions.SecureMessagingException;
import core.ISO7816_4.APDU;
import core.ISO7816_4.CAPDU;
import core.ISO7816_4.RAPDU;
import core.ISO7816_4.Responses;
import core.ISO7816_4.SecureMessaging.SecureMessaging;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;
import core.Support.HelperClass;

/**
 * This class can be used as API connection to send and receive data to and from
 * the opposite side.
 * 
 * @author Mark Forjahn
 * 
 */
public class JCard {
	private DeviceType deviceType; // Actual device
	private SecureMessaging secureMessaging; // encryption/ decryption module
	private IConnection connection; // "physical" connection
	private APDU lastReceivedData; // contains the last received message from
									// the opposite side

	public JCard(IConnection connection,
			DeviceType deviceType) {
		this.connection = connection;
		this.deviceType = deviceType;
	}

	public JCard(IConnection connection,
			DeviceType deviceType,
			SecureMessaging secureMessaging,
			APDU lastReceivedData) {
		this.connection = connection;
		this.deviceType = deviceType;
		this.secureMessaging = secureMessaging;
		this.lastReceivedData = lastReceivedData;
	}

	public APDU getLastReceivedData(LogState state)
			throws SecureMessagingException {

		if (lastReceivedData instanceof CAPDU
				&& isEncryptionEnabled()) {
			Log.addEntry("Decrypt capdu now...",
					LogType.INFORMATION, state,
					LogLevel.LOW);
			try {
				lastReceivedData = secureMessaging
						.decryptCAPDU(
								(CAPDU) lastReceivedData,
								state);
			} catch (SecureMessagingException e) {
				if (e.getStatusBytes() != null) {
					try {
						Log.addEntry(
								"Inform pcd about error now ...: "
										+ HelperClass
												.toHexString(e
														.getStatusBytes()),
								LogType.WARNING, state,
								LogLevel.LOW);
						secureMessaging = null; // Sending without sm
						sendRAPDU(
								new RAPDU(
										e.getStatusBytes(),
										state), state);
					} catch (InvalidActionException e1) {
						Log.addEntry(
								"Secure messaging error - could not inform pcd about error: "
										+ HelperClass
												.toHexString(e
														.getStatusBytes()),
								LogType.WARNING, state,
								LogLevel.LOW);
					} catch (ConnectionException e1) {
						Log.addEntry(
								"Secure messaging error - could not inform pcd about error: "
										+ HelperClass
												.toHexString(e
														.getStatusBytes()),
								LogType.WARNING, state,
								LogLevel.LOW);
					} catch (InvalidRAPDUException e1) {
						Log.addEntry(
								"Secure messaging error - could not inform pcd about error: "
										+ HelperClass
												.toHexString(e
														.getStatusBytes()),
								LogType.WARNING, state,
								LogLevel.LOW);
					} catch (InvalidCAPDUException e1) {
						Log.addEntry(
								"Secure messaging error - could not inform pcd about error: "
										+ HelperClass
												.toHexString(e
														.getStatusBytes()),
								LogType.WARNING, state,
								LogLevel.LOW);
					}
				}
				throw e;
			}
			Log.addEntry(
					"Decrypted capdu: "
							+ HelperClass
									.toHexString(lastReceivedData
											.getBytes()),
					LogType.INFORMATION, state,
					LogLevel.LOW);
		} else if (lastReceivedData instanceof RAPDU
				&& isEncryptionEnabled()) {
			if (HelperClass
					.toHexString(
							((RAPDU) lastReceivedData)
									.getSW())
					.equals(HelperClass
							.toHexString(Responses.SECURE_MESSAGING_MISSING_DATA_OBJECTS))
					|| HelperClass
							.toHexString(
									((RAPDU) lastReceivedData)
											.getSW())
							.equals(HelperClass
									.toHexString(Responses.SECURE_MESSAGING_WRONG_DATA_OBJECTS))) {
				throw new SecureMessagingException(
						"picc responded error: "
								+ HelperClass.toHexString(((RAPDU) lastReceivedData)
										.getSW()), state);

			}
			Log.addEntry("Decrypt rapdu now...",
					LogType.INFORMATION, state,
					LogLevel.LOW);
			lastReceivedData = secureMessaging
					.decryptRAPDU((RAPDU) lastReceivedData,
							state);
			Log.addEntry(
					"Decrypted rapdu: "
							+ HelperClass
									.toHexString(lastReceivedData
											.getBytes()),
					LogType.INFORMATION, state,
					LogLevel.LOW);
		}

		return this.lastReceivedData;
	}

	public void sendRAPDU(RAPDU rapdu, LogState state)
			throws InvalidActionException,
			ConnectionException, InvalidRAPDUException,
			InvalidCAPDUException, SecureMessagingException {
		if (deviceType.equals(DeviceType.PCD)) {
			throw new InvalidActionException(
					"reader cannot send radpu -> send capdu instead!",
					state);
		} else {
			if (isEncryptionEnabled()) {
				Log.addEntry("Encrypt rapdu now...",
						LogType.INFORMATION, state,
						LogLevel.LOW);
				rapdu = secureMessaging.encryptRAPDU(rapdu,
						state);
				Log.addEntry(
						"Encrypted rapdu: "
								+ HelperClass.toHexString(rapdu
										.getBytes()),
						LogType.INFORMATION, state,
						LogLevel.LOW);
			}
			lastReceivedData = (CAPDU) connection.send(
					rapdu, state);
		}
	}

	public void sendCAPDU(CAPDU capdu, LogState state)
			throws InvalidActionException,
			ConnectionException, InvalidRAPDUException,
			InvalidCAPDUException, SecureMessagingException {
		if (deviceType.equals(DeviceType.PICC)) {
			throw new InvalidActionException(
					"chipcard cannot send cadpu -> send rapdu instead!",
					state);
		} else {
			if (isEncryptionEnabled()) {
				Log.addEntry("Encrypt capdu now...",
						LogType.INFORMATION, state,
						LogLevel.LOW);
				capdu = secureMessaging.encryptCAPDU(capdu,
						state);
				Log.addEntry(
						"Encrypted capdu: "
								+ HelperClass.toHexString(capdu
										.getBytes()),
						LogType.INFORMATION, state,
						LogLevel.LOW);
			}
			lastReceivedData = (RAPDU) connection.send(
					capdu, state);
		}
	}

	public boolean isEncryptionEnabled() {
		return secureMessaging == null ? false : true;
	}

	public void closeConnection() {
		connection.closeConnection();
	}

}
