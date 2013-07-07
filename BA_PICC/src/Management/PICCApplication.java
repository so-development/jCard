package Management;

import android.app.Activity;
import android.content.Intent;
import core.Application.Application;
import core.Exceptions.ApplicationStartingException;
import core.Logging.LogState;

/**
 * This class contains information to be able to start dynamically activities of
 * specific applications
 * 
 * @author Mark Forjahn
 * 
 */
public class PICCApplication extends Application {
	private Activity mainActivity;
	private String activityDestination;

	public PICCApplication(String name, byte[] aid,
			Activity mainActivity,
			String activityDestination) {
		super(name, aid);
		this.mainActivity = mainActivity;
		this.activityDestination = activityDestination;
	}

	@Override
	public void startApplication()
			throws ApplicationStartingException {
		Class cl;
		Activity activity = null;
		try {
			cl = Class.forName(activityDestination);
			activity = (Activity) cl.newInstance();
		} catch (Exception e) {
			throw new ApplicationStartingException(
					e.getMessage(),
					LogState.APPLICATION_STARTING);
		}
		JCardTransportClass.setJcard(jcard);
		Intent intent = new Intent(mainActivity,
				activity.getClass());
		mainActivity.startActivity(intent);

	}

}
