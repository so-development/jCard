package core.ISO7816_4;

import core.Exceptions.InvalidCAPDUException;
import core.Logging.LogState;

/**
 * This class represents the Command APDU.
 * 
 * @author Mark Forjahn
 * 
 */
public class CAPDU extends APDU {

	private byte cla;
	private byte ins;
	private byte p1;
	private byte p2;
	private byte lc;
	private byte le;

	private boolean lcIsSet = false;
	private boolean leIsSet = false;

	public CAPDU(byte cla, byte ins, byte p1, byte p2) {
		this.cla = cla;
		this.ins = ins;
		this.p1 = p1;
		this.p2 = p2;
	}

	public CAPDU(byte cla, byte ins, byte p1, byte p2,
			byte[] data, LogState state)
			throws InvalidCAPDUException {
		super(data);
		this.cla = cla;
		this.ins = ins;
		this.p1 = p1;
		this.p2 = p2;

		if (data != null) {
			this.lc = (byte) data.length;
			this.lcIsSet = true;
		}

		if (data.length > 253) {
			throw new InvalidCAPDUException(
					"Too much data for one CAPDU: "
							+ data.length, state);
		}

	}

	public CAPDU(byte cla, byte ins, byte p1, byte p2,
			byte le) {
		this.cla = cla;
		this.ins = ins;
		this.p1 = p1;
		this.p2 = p2;

		this.le = le;
		this.leIsSet = true;
	}

	public CAPDU(byte cla, byte ins, byte p1, byte p2,
			byte[] data, byte le, LogState state)
			throws InvalidCAPDUException {
		super(data);
		this.cla = cla;
		this.ins = ins;
		this.p1 = p1;
		this.p2 = p2;

		if (data != null) {
			this.lc = (byte) data.length;
			this.lcIsSet = true;
		}

		this.le = le;
		this.leIsSet = true;

		if (data.length > 253) {
			throw new InvalidCAPDUException(
					"Too much data for one CAPDU: "
							+ data.length, state);
		}
	}

	public byte getCLA() {
		return cla;
	}

	public byte getINS() {
		return ins;
	}

	public byte getP1() {
		return p1;
	}

	public byte getP2() {
		return p2;
	}

	public byte getLc() {
		return lc;
	}

	public byte getLe() {
		return le;
	}

	@Override
	public byte[] getBytes() {
		int byteCounter = 0;

		if (leIsSet) {
			byteCounter++;
		}
		if (lcIsSet) {
			byteCounter++;
			byteCounter += super.getData().length;
		}

		byte[] bytes = new byte[4 + byteCounter];

		bytes[0] = cla;
		bytes[1] = ins;
		bytes[2] = p1;
		bytes[3] = p2;

		// consider all 4 possibilities
		if (lcIsSet) {
			bytes[4] = lc;
			for (int i = 0; i < data.length; i++) {
				bytes[5 + i] = data[i];
			}
		}

		if (leIsSet) {
			bytes[bytes.length - 1] = le;
		}
		return bytes;
	}

	public byte[] getHeader() {
		byte[] header = new byte[4];
		header[0] = getCLA();
		header[1] = getINS();
		header[2] = getP1();
		header[3] = getP2();

		return header;
	}
}
