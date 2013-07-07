package core.Exceptions;

import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;

public class SecureMessagingException extends Exception {

	/**
	 * 
	 */
	private byte[] statusBytes = null;
	private static final long serialVersionUID = 1L;

	public SecureMessagingException(String str,
			LogState state) {
		super(str);
		Log.addEntry("Error in secure messaging",
				LogType.ERROR, state, LogLevel.HIGH);
		Log.addEntry(str, LogType.ERROR, state,
				LogLevel.LOW);
	}

	public SecureMessagingException(String str,
			byte[] statusBytes, LogState state) {
		super(str);
		this.statusBytes = statusBytes;
		Log.addEntry("Error in secure messaging",
				LogType.ERROR, state, LogLevel.HIGH);
		Log.addEntry(str, LogType.ERROR, state,
				LogLevel.LOW);
	}

	public byte[] getStatusBytes() {
		return this.statusBytes;
	}
}
