package core.Exceptions;

import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;

public class CryptoException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public CryptoException(String str, LogState state) {
		super(str);
		Log.addEntry("Error in crypto functions",
				LogType.ERROR, state, LogLevel.HIGH);
		Log.addEntry(str, LogType.ERROR, state,
				LogLevel.LOW);

	}
}
