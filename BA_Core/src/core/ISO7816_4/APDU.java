package core.ISO7816_4;

/**
 * This class contains elements, that all APDUs (Command APDU / Response APDU)
 * can contain. The new APDU framework was established to be able to program
 * with consistent APDUs. Otherwise Smartcardio-APDUs on PCD side and direct
 * byte input on PICC side would had to be used.
 * 
 * Child classes are: {@link CAPDU} {@link RAPDU}
 * 
 * @author Mark Forjahn
 * 
 */
public abstract class APDU {

	protected byte[] data; // each APDU can contain additional data

	public APDU() {
	}

	public APDU(byte[] data) {
		this.data = data;
	}

	public byte[] getData() {
		return data;
	}

	public abstract byte[] getBytes();

}
