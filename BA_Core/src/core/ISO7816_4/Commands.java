package core.ISO7816_4;

import core.Exceptions.InvalidCAPDUException;
import core.Logging.LogState;

/**
 * Contains a series of commands for easier programming
 * 
 * @author Mark Forjahn
 * 
 */
public class Commands {

	public static final CAPDU createAIDCommand(byte[] aid)
			throws InvalidCAPDUException {
		return new CAPDU((byte) 0x00, (byte) 0xA4,
				(byte) 0x04, (byte) 0x00, aid, (byte) 0x00,
				LogState.INITIALIZE_APPLICATION_ID);
	}

}
