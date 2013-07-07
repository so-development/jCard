package core.ISO7816_4;

import core.Exceptions.InvalidRAPDUException;
import core.Logging.LogState;

/**
 * This class represents the Response APDU
 * 
 * @author Mark Forjahn
 * 
 */
public class RAPDU extends APDU {

	private byte sw1;
	private byte sw2;

	public RAPDU(byte[] data, byte sw1, byte sw2,
			LogState state) throws InvalidRAPDUException {
		super(data);
		this.sw1 = sw1;
		this.sw2 = sw2;

		if (data != null) {
			if (data.length > 255) {
				throw new InvalidRAPDUException(
						"Too much data for one RAPDU: "
								+ data.length, state);
			}
		}

	}

	public RAPDU(byte sw1, byte sw2)
			throws InvalidRAPDUException {
		this.sw1 = sw1;
		this.sw2 = sw2;
	}

	public RAPDU(byte[] data, byte[] sw, LogState state)
			throws InvalidRAPDUException {
		super(data);

		if (sw == null) {
			throw new InvalidRAPDUException(
					"sw1/sw2 must not be null!", state);
		}
		if (sw.length == 1) {
			this.sw1 = sw[0];
			this.sw2 = 0x00;

		} else if (sw.length == 2) {
			this.sw1 = sw[0];
			this.sw2 = sw[1];
		} else {
			throw new InvalidRAPDUException(
					"do not use more than two sw-bytes!",
					state);
		}

		if (data != null) {
			if (data.length > 255) {
				throw new InvalidRAPDUException(
						"Too much data for one RAPDU: "
								+ data.length, state);
			}
		}
	}

	public RAPDU(byte[] sw, LogState state)
			throws InvalidRAPDUException {
		super(null);

		if (sw == null) {
			throw new InvalidRAPDUException(
					"sw1/sw2 must not be null!", state);
		}
		if (sw.length == 1) {
			this.sw1 = sw[0];
			this.sw2 = 0x00;

		} else if (sw.length == 2) {
			this.sw1 = sw[0];
			this.sw2 = sw[1];
		} else {
			throw new InvalidRAPDUException(
					"do not use more than two sw-bytes!",
					state);
		}
	}

	public byte getSW1() {
		return sw1;
	}

	public byte getSW2() {
		return sw2;
	}

	@Override
	public byte[] getBytes() {
		int byteCounter = 2;

		if (data != null) {
			byteCounter += data.length;
		}

		byte[] bytes = new byte[byteCounter];

		bytes[0] = sw1;
		bytes[1] = sw2;

		if (data != null) {
			for (int i = 0; i < data.length; i++) {
				bytes[i] = data[i];
			}
		}
		bytes[byteCounter - 2] = sw1;
		bytes[byteCounter - 1] = sw2;

		return bytes;

	}

	public byte[] getSW() {
		byte[] b = new byte[2];

		b[0] = sw1;
		b[1] = sw2;
		return b;
	}
}
