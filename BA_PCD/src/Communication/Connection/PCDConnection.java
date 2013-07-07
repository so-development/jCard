package Communication.Connection;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import core.Communication.Connection.IConnection;
import core.Exceptions.ConnectionException;
import core.Exceptions.InvalidRAPDUException;
import core.ISO7816_4.APDU;
import core.ISO7816_4.RAPDU;
import core.ISO7816_4.CAPDU;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;
import core.Support.HelperClass;

/**
 * Transmits and receives data by using smartcardio
 * 
 * @author Mark Forjahn
 * 
 */
public class PCDConnection implements IConnection {

	private Card card;
	private CardTerminals terminals;
	private CardChannel channel;

	@Override
	public void initialize() throws ConnectionException {
		TerminalFactory factory = TerminalFactory
				.getDefault();
		terminals = factory.terminals();
		card = null;
		try {
			if (terminals.list().isEmpty()) {
				throw new ConnectionException(
						"No smart card readers found. Connect reader and try again.",
						LogState.INITIALIZE_JCARD);
			}
		} catch (CardException e1) {
			throw new ConnectionException(e1.getMessage(),
					LogState.INITIALIZE_JCARD);
		}

		Log.addEntry("Place phone/card on reader to start",
				LogType.INFORMATION,
				LogState.INITIALIZE_JCARD, LogLevel.HIGH);
		try {
			card = waitForCard(terminals);
		} catch (CardException e) {
			throw new ConnectionException(e.getMessage(),
					LogState.INITIALIZE_JCARD);
		}

	}

	@Override
	public void connect() throws ConnectionException {
		try {
			card.beginExclusive();
		} catch (CardException e) {
			throw new ConnectionException(e.getMessage(),
					LogState.INITIALIZE_JCARD);
		}
		channel = card.getBasicChannel();
	}

	@Override
	public APDU send(APDU data, LogState state)
			throws ConnectionException,
			InvalidRAPDUException {
		CommandAPDU apdu = mapCAPDU((CAPDU) data, state);
		try {
			return mapRAPDU(transmit(apdu), state);
		} catch (CardException e) {
			throw new ConnectionException(e.getMessage(),
					state);
		}
	}

	private CommandAPDU mapCAPDU(CAPDU capdu, LogState state)
			throws ConnectionException {
		Log.addEntry(
				"Mapping CAPDU -> javax.smartcardio.CommandAPDU",
				LogType.INFORMATION, state, LogLevel.LOW);
		Log.addEntry(
				"(old) CAPDU (structured) : "
						+ "  CLA: "
						+ HelperClass.toHexString(capdu
								.getCLA())
						+ " INS: "
						+ HelperClass.toHexString(capdu
								.getINS())
						+ "  P1: "
						+ HelperClass.toHexString(capdu
								.getP1())
						+ "  P2: "
						+ HelperClass.toHexString(capdu
								.getP2())
						+ "  LC: "
						+ HelperClass.toHexString(capdu
								.getLc())
						+ "  Data: "
						+ HelperClass.toHexString(capdu
								.getData())
						+ "  LE: "
						+ HelperClass.toHexString(capdu
								.getLe()),
				LogType.INFORMATION, state, LogLevel.LOW);
		Log.addEntry(
				"(old) CAPDU (bytes): "
						+ HelperClass.toHexString(capdu
								.getBytes()),
				LogType.INFORMATION, state, LogLevel.LOW);

		CommandAPDU apdu = new CommandAPDU(capdu.getBytes());
		Log.addEntry("(new) CommandAPDU (bytes): "
				+ HelperClass.toHexString(apdu.getBytes()),
				LogType.INFORMATION, state, LogLevel.LOW);

		if (HelperClass.toHexString(capdu.getBytes())
				.equals(HelperClass.toHexString(apdu
						.getBytes()))) {
			Log.addEntry("CAPDU mapping succeeded!",
					LogType.INFORMATION, state,
					LogLevel.LOW);
		} else {
			throw new ConnectionException(
					"Mapping CAPDU -> javax.smartcardio.CommandAPDU failed!",
					state);
		}
		Log.addEntry("Transmit data now ...",
				LogType.INFORMATION, state, LogLevel.LOW);

		return apdu;
	}

	private RAPDU mapRAPDU(ResponseAPDU rapdu,
			LogState state) throws InvalidRAPDUException,
			ConnectionException {
		Log.addEntry("Data received", LogType.INFORMATION,
				state, LogLevel.LOW);
		Log.addEntry(
				"Mapping javax.smartcardio.ResponseAPDU -> RAPDU",
				LogType.INFORMATION, state, LogLevel.LOW);

		RAPDU apdu = new RAPDU(rapdu.getData(),
				(byte) rapdu.getSW1(),
				(byte) rapdu.getSW2(), state);

		Log.addEntry("(old) ResponseAPDU (bytes): "
				+ HelperClass.toHexString(apdu.getBytes()),
				LogType.INFORMATION, state, LogLevel.LOW);

		Log.addEntry(
				"(new) RAPDU (structured): "
						+ "  SW1: "
						+ HelperClass.toHexString(apdu
								.getSW1())
						+ " SW2: "
						+ HelperClass.toHexString(apdu
								.getSW2())
						+ (apdu.getData() != null ? "  Data: "
								+ HelperClass
										.toHexString(apdu
												.getData())
								: ""), LogType.INFORMATION,
				state, LogLevel.LOW);

		if (HelperClass.toHexString(rapdu.getBytes())
				.equals(HelperClass.toHexString(apdu
						.getBytes()))) {
			Log.addEntry("RAPDU mapping succeeded!",
					LogType.INFORMATION, state,
					LogLevel.LOW);
		} else {
			throw new ConnectionException(
					"Mapping javax.smartcardio.ResponseAPDU -> RAPDU failed!",
					state);
		}

		return apdu;
	}

	private ResponseAPDU transmit(CommandAPDU cmd)
			throws CardException {
		ResponseAPDU response = channel.transmit(cmd);
		return response;
	}

	private Card waitForCard(CardTerminals terminals)
			throws CardException {
		while (true) {
			for (CardTerminal ct : terminals
					.list(CardTerminals.State.CARD_INSERTION)) {

				return ct.connect("T=1");
			}
			terminals.waitForChange();
		}
	}

	@Override
	public void closeConnection() {
		try {
			card.endExclusive();
			card.disconnect(true);
		} catch (Exception e) {
			Log.addEntry("Could not close connection",
					LogType.WARNING,
					LogState.INITIALIZE_JCARD, LogLevel.LOW);
		}
	}
}
