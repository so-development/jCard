package core.Exceptions;

import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;

public class ApplicationStartingException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public ApplicationStartingException(String str,
			LogState state) {
		Log.addEntry(
				"Error while starting the application",
				LogType.ERROR, state, LogLevel.HIGH);
		Log.addEntry(str, LogType.ERROR, state,
				LogLevel.LOW);
	}

}
