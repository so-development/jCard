package core.Logging;

import java.io.Serializable;

/**
 * This class represents an log entry
 * 
 * @author Mark Forjahn
 * 
 */
public class Entry implements Serializable {

	private static final long serialVersionUID = -1544637036585229094L;
	private String log; // Log entry as string
	private LogType type; // error, warning, info
	private LogState state; // initializing, authenticating, application
							// starting, ...
	private LogLevel level; // high-/low level

	public Entry(String log, LogType type, LogState state,
			LogLevel level) {
		this.log = log;
		this.state = state;
		this.type = type;
		this.level = level;
	}

	public LogState getLogState() {
		return this.state;
	}

	public LogType getLogType() {
		return this.type;
	}

	public LogLevel getLogLevel() {
		return this.level;
	}

	public String getLog() {
		return this.log;
	}

}
