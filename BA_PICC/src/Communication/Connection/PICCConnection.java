package Communication.Connection;

import java.io.IOException;

import core.Communication.Connection.IConnection;
import core.Exceptions.ConnectionException;
import core.Exceptions.InvalidCAPDUException;
import core.ISO7816_4.APDU;
import core.ISO7816_4.CAPDU;
import core.ISO7816_4.RAPDU;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;
import core.Support.HelperClass;

import android.nfc.Tag;

public class PICCConnection implements IConnection {

	private Tag tag;
	private String tech;
	private TagWrapper tw;

	public PICCConnection(Tag tag, String tech) {
		this.tag = tag;
		this.tech = tech;
	}

	@Override
	public void initialize() {
		tw = new TagWrapper(tag, tech);

	}

	@Override
	public void connect() throws ConnectionException {
		if (!tw.isConnected()) {
			try {
				tw.connect();
			} catch (IOException e) {
				throw new ConnectionException(
						e.getMessage(),
						LogState.INITIALIZE_JCARD);
			}
		}
	}

	@Override
	public APDU send(APDU data, LogState state)
			throws ConnectionException {
		byte[] dataToSend = mapRAPDU((RAPDU) data, state);

		try {
			return mapCAPDU(tw.transceive(dataToSend),
					state);
		} catch (IOException e) {
			Log.addEntry("I/O Exception", LogType.WARNING,
					state, LogLevel.HIGH);
			Log.addEntry(e.getMessage(), LogType.WARNING,
					state, LogLevel.LOW);
		} catch (InvalidCAPDUException e) {
		}
		return null;

	}

	private byte[] mapRAPDU(RAPDU rapdu, LogState state)
			throws ConnectionException {

		Log.addEntry("Mapping RAPDU -> byte[]",
				LogType.INFORMATION, state, LogLevel.LOW);

		Log.addEntry(
				"(old) RAPDU (structured): "
						+ "  SW1: "
						+ HelperClass.toHexString(rapdu
								.getSW1())
						+ " SW2: "
						+ HelperClass.toHexString(rapdu
								.getSW2())
						+ (rapdu.getData() != null ? "  Data: "
								+ HelperClass
										.toHexString(rapdu
												.getData())
								: ""), LogType.INFORMATION,
				state, LogLevel.LOW);
		Log.addEntry(
				"(old) RAPDU (bytes): "
						+ HelperClass.toHexString(rapdu
								.getBytes()),
				LogType.INFORMATION, state, LogLevel.LOW);
		System.out.println();

		byte[] apdu = rapdu.getBytes();
		Log.addEntry(
				"(new) Bytes (bytes): "
						+ HelperClass.toHexString(apdu),
				LogType.INFORMATION, state, LogLevel.LOW);

		if (HelperClass.toHexString(rapdu.getBytes())
				.equals(HelperClass.toHexString(apdu))) {
			Log.addEntry("RAPDU mapping succeeded!",
					LogType.INFORMATION, state,
					LogLevel.LOW);
		} else {
			throw new ConnectionException(
					"Mapping RAPDU -> byte[] failed!",
					state);
		}

		Log.addEntry("Transmit data now ...",
				LogType.INFORMATION, state, LogLevel.LOW);
		return apdu;
	}

	private CAPDU mapCAPDU(byte[] capdu, LogState state)
			throws InvalidCAPDUException,
			ConnectionException {
		Log.addEntry("Data received", LogType.INFORMATION,
				state, LogLevel.LOW);
		CAPDU apdu;

		byte cla = capdu[0];
		byte ins = capdu[1];
		byte p1 = capdu[2];
		byte p2 = capdu[3];

		Log.addEntry("Mapping byte[] -> CAPDU",
				LogType.INFORMATION, state, LogLevel.LOW);
		Log.addEntry(
				"(old) Bytes (bytes): "
						+ HelperClass.toHexString(capdu),
				LogType.INFORMATION, state, LogLevel.LOW);

		if (capdu.length > 4) {
			// just one more byte exists -> le
			if (capdu.length == 5) {
				byte le = capdu[capdu.length - 1];
				apdu = new CAPDU(cla, ins, p1, p2, le);
			}
			// more bytes exist -> at least lc
			else {
				byte lc = capdu[4];

				byte[] data = new byte[HelperClass
						.byteToInt(lc)];

				// Header + lc + data OR Header + lc + data + le
				if (capdu.length == 5 + data.length
						|| capdu.length == 5 + data.length + 1) {
					if (data.length > 0) {
						for (int i = 5; i < data.length + 5; i++) {
							data[i - 5] = capdu[i];
						}
					}
				} else {
					throw new InvalidCAPDUException(
							"lc does not match with length of data",
							state);
				}

				if (capdu.length == 5 + data.length + 1) {
					byte le = capdu[capdu.length - 1];
					apdu = new CAPDU(cla, ins, p1, p2,
							data, le, state);
				} else {
					apdu = new CAPDU(cla, ins, p1, p2,
							data, state);
				}
			}
		} else {
			apdu = new CAPDU(cla, ins, p1, p2);
		}

		Log.addEntry(
				"(new) CAPDU (structured) : "
						+ "  CLA: "
						+ HelperClass.toHexString(apdu
								.getCLA())
						+ " INS: "
						+ HelperClass.toHexString(apdu
								.getINS())
						+ "  P1: "
						+ HelperClass.toHexString(apdu
								.getP1())
						+ "  P2: "
						+ HelperClass.toHexString(apdu
								.getP2())
						+ "  LC: "
						+ HelperClass.toHexString(apdu
								.getLc())
						+ "  Data: "
						+ HelperClass.toHexString(apdu
								.getData())
						+ "  LE: "
						+ HelperClass.toHexString(apdu
								.getLe()),
				LogType.INFORMATION, state, LogLevel.LOW);

		if (HelperClass.toHexString(apdu.getBytes())
				.equals(HelperClass.toHexString(capdu))) {
			Log.addEntry("CAPDU mapping succeeded!",
					LogType.INFORMATION, state,
					LogLevel.LOW);
		} else {
			throw new ConnectionException(
					"Mapping byte[] -> CAPDU failed!",
					state);
		}

		return apdu;
	}

	@Override
	public void closeConnection() {
		try {
			if (tw.isConnected()) {
				tw.close();
			}
		} catch (IOException e) {
			Log.addEntry("Could not close connection",
					LogType.WARNING,
					LogState.INITIALIZE_JCARD, LogLevel.LOW);
		}
	}

}
