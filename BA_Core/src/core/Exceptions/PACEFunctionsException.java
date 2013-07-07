package core.Exceptions;

import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;

public class PACEFunctionsException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6802999342098121591L;

	public PACEFunctionsException(String str, LogState state) {
		super(str);
		Log.addEntry("Error in PACE function",
				LogType.ERROR, state, LogLevel.HIGH);
		Log.addEntry(str, LogType.ERROR, state,
				LogLevel.LOW);
	}
}
