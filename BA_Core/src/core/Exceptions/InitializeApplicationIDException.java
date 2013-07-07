package core.Exceptions;

import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;

public class InitializeApplicationIDException extends
		Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public InitializeApplicationIDException(String str,
			LogState state) {
		super(str);
		Log.addEntry(
				"Error while initializing application id",
				LogType.ERROR, state, LogLevel.HIGH);
		Log.addEntry(str, LogType.ERROR, state,
				LogLevel.LOW);

	}

}
