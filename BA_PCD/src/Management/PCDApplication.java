package Management;

import java.lang.reflect.Method;

import core.Application.Application;
import core.Application.IPCDApplication;
import core.Communication.JCard;
import core.Exceptions.ApplicationStartingException;
import core.Logging.LogState;
import core.Management.AppData;

/**
 * Interface to PCD application
 * 
 * @author Mark Forjahn
 * 
 */
public class PCDApplication extends Application {

	private String programmDestination;

	public PCDApplication(String name, byte[] aid,
			String programmDestination) {
		super(name, aid);
		this.programmDestination = programmDestination;
	}

	@Override
	public void startApplication()
			throws ApplicationStartingException {
		Class<IPCDApplication> cl;
		Object obj = null;
		Method method;
		try {
			cl = (Class<IPCDApplication>) Class
					.forName(programmDestination);
			obj = cl.newInstance();
			method = obj.getClass().getMethod("start",
					JCard.class, AppData.class);
			method.invoke(obj, jcard, appData);
		} catch (Exception e) {
			throw new ApplicationStartingException(
					e.getMessage(),
					LogState.APPLICATION_STARTING);
		}

	}

}
