package core.ISO7816_4;

/**
 * Contains a series of responses for easier programming
 * 
 * @author Mark Forjahn
 * 
 */
public class Responses {

	public static final byte[] SUCCESS = { (byte) 0x90,
			(byte) 0x00 };
	public static final byte[] SECURE_MESSAGING_MISSING_DATA_OBJECTS = {
			(byte) 0x69, (byte) 0x87 };
	public static final byte[] SECURE_MESSAGING_WRONG_DATA_OBJECTS = {
			(byte) 0x69, (byte) 0x88 };

}
