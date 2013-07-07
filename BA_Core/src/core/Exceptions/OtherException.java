package core.Exceptions;

import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;

public class OtherException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6802999342098121591L;

	public OtherException(String str, LogState state) {
		super(str);
		Log.addEntry("Error", LogType.ERROR, state,
				LogLevel.HIGH);
		Log.addEntry(str, LogType.ERROR, state,
				LogLevel.LOW);

	}
}
