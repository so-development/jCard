package core.Support;

/**
 * This class is used in connection to class "StopWatch", for storing the
 * measured time.
 * 
 * @author Mark
 * 
 */
public class Time {

	private int seconds;
	private int milliseconds;

	public int getSeconds() {
		return seconds;
	}

	public int getMilliseconds() {
		return milliseconds;
	}

	public void addTime(int count) {
		this.milliseconds = milliseconds + count;
		this.seconds = milliseconds / 1000;
	}

}
