package core.Logging;

import java.util.ArrayList;

/**
 * This class handles all creates log entries and gives them back
 * 
 * @author Mark Forjahn
 * 
 */
public class Log {

	private static ArrayList<Entry> entries = new ArrayList<Entry>(); // contains
																		// all
																		// entries

	public static void addEntry(String log, LogType type,
			LogState state, LogLevel level) {
		entries.add(new Entry(log, type, state, level));

		if (state.equals(LogState.INITIALIZE_JCARD)) {
			System.out.print("_Initialize JCard_ ");
		} else if (state
				.equals(LogState.INITIALIZE_APPLICATION_ID)) {
			System.out
					.print("_Initialize application id_ ");
		} else if (state.equals(LogState.AUTHENTICATE)) {
			System.out.print("_Authenticate_ ");
		} else if (state
				.equals(LogState.APPLICATION_STARTING)) {
			System.out.print("_Application starting_ ");
		} else if (state
				.equals(LogState.APPLICATION_STARTED)) {
			System.out.print("_Application started_ ");
		} else if (state
				.equals(LogState.APPLICATION_STARTED)) {
			System.out.print("_Unknown_ ");
		}

		if (type.equals(LogType.INFORMATION)) {
			System.out.print("Information");
		} else if (type.equals(LogType.WARNING)) {
			System.out.print("Warning");
		} else if (type.equals(LogType.ERROR)) {
			System.out.print("Error");
		}

		if (level.equals(LogLevel.LOW)) {
			System.out.print("_Log level: " + "low\n");
		} else if (level.equals(LogLevel.HIGH)) {
			System.out.print("_Log level: " + "high\n");
		}
		System.out.print(log + "\n\n");
	}

	public static ArrayList<Entry> getEntries(LogType type) {
		ArrayList<Entry> returnEntries = new ArrayList<Entry>();

		if (type.equals(LogType.ERROR)) {
			for (Entry entry : entries) {
				if (entry.getLogType()
						.equals(LogType.ERROR)) {
					returnEntries.add(entry);
				}
			}
		} else if (type.equals(LogType.WARNING)) {
			for (Entry entry : entries) {
				if (entry.getLogType()
						.equals(LogType.ERROR)
						|| entry.getLogType().equals(
								LogType.WARNING)) {
					returnEntries.add(entry);
				}
			}
		} else if (type.equals(LogType.INFORMATION)) {
			return entries;
		}

		return returnEntries;
	}

	public static ArrayList<Entry> getEntries(
			boolean logState1, boolean logState2,
			boolean logState3, boolean logState4,
			boolean logState5, LogLevel level) {
		ArrayList<Entry> returnEntries = new ArrayList<Entry>();

		for (Entry entry : entries) {
			if (entry.getLogLevel().equals(level)) {
				if (logState1
						&& entry.getLogState().equals(
								LogState.INITIALIZE_JCARD)) {
					returnEntries.add(entry);
				} else if (logState2
						&& entry.getLogState().equals(
								LogState.AUTHENTICATE)) {
					returnEntries.add(entry);
				} else if (logState3
						&& entry.getLogState()
								.equals(LogState.INITIALIZE_APPLICATION_ID)) {
					returnEntries.add(entry);
				} else if (logState4
						&& entry.getLogState()
								.equals(LogState.APPLICATION_STARTING)) {
					returnEntries.add(entry);
				} else if (logState5
						&& entry.getLogState()
								.equals(LogState.APPLICATION_STARTED)) {
					returnEntries.add(entry);
				} else if (logState5
						&& entry.getLogState().equals(
								LogState.UNKNOWN)) {
					returnEntries.add(entry);
				}
			}
		}
		return returnEntries;
	}

	public static ArrayList<Entry> getEntries(LogType type,
			LogState state, LogLevel level) {
		ArrayList<Entry> returnEntries = new ArrayList<Entry>();

		if (type.equals(LogType.ERROR)) {
			for (Entry entry : entries) {
				if (entry.getLogLevel().equals(level)
						&& entry.getLogState()
								.equals(state)
						&& (entry.getLogType()
								.equals(LogType.ERROR))) {
					returnEntries.add(entry);
				}
			}
		} else if (type.equals(LogType.WARNING)) {
			for (Entry entry : entries) {
				if (entry.getLogLevel().equals(level)
						&& entry.getLogState()
								.equals(state)
						&& (entry.getLogType().equals(
								LogType.ERROR) || entry
								.getLogType().equals(
										LogType.WARNING))) {
					returnEntries.add(entry);
				}
			}
		} else if (type.equals(LogType.INFORMATION)) {

			for (Entry entry : entries) {
				if (entry.getLogLevel().equals(level)
						&& entry.getLogState()
								.equals(state)) {
					returnEntries.add(entry);
				}
			}
		}

		return returnEntries;
	}

	public static void reset() {
		Log.entries.clear();
	}
}
