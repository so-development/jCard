package core.Crypto;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;

/**
 * This class creates secure random values
 * @author Mark Forjahn
 *
 */
public class RandomCreator {
	

	/**
	 * Creates secure bits
	 * @param size size of bits that should be generated
	 * @return random bits
	 * @throws NoSuchAlgorithmException 
	 */
	public static byte [] createSecureRandomBytes (int bits, LogState state) throws NoSuchAlgorithmException {
		
		SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
		
		if ( (bits % 8) != 0 ) {
		   Log.addEntry("Bits not divisible by 8 without remainder - Could cause problems with keys", LogType.INFORMATION, state, LogLevel.LOW);
		}
	    final byte [] bytes = new byte[ bits / 8 ];	    
	    rand.nextBytes(bytes);
	    
	    return bytes;		
	}

	/**
	 * Creates secure int values
	 * @param max max int value to create
	 * @return random int
	 * @throws NoSuchAlgorithmException
	 */
	public static int createSecureRandomInt (int max) throws NoSuchAlgorithmException {
		
		SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
		 int retInt = 0;
		 while(!(retInt <= 999999 && retInt >= 100000)){
			 retInt = rand.nextInt(max);
		 }	    
	    return retInt;
		
	}
}
