package core.Support;

import java.util.Timer;
import java.util.TimerTask;

/**
 * This class allows to perform timing.
 * 
 * @author Mark
 * 
 */
public class StopWatch extends Thread {

	private Time time;
	private TimerTask task;

	public StopWatch() {
		this.time = new Time();
	}

	@Override
	public void run() {
		final Timer timer = new Timer();
		task = new TimerTask() {
			public void run() {
				synchronized (time) {
					time.addTime(1);
				}
			}
		};
		timer.scheduleAtFixedRate(task, 0, 1);
	}

	public int getMilliSeconds() {
		synchronized (time) {
			task.cancel();
			return time.getMilliseconds();
		}
	}

}
