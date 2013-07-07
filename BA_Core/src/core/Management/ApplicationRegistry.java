package core.Management;

import java.util.HashSet;


import core.Application.Application;
import core.Exceptions.AIDNotFoundException;
import core.Logging.LogState;
import core.Support.HelperClass;

/**
 * This class handles all applications (i.e. PKI Applet Emulator) Each
 * application can be identified by an specific aid (application id)
 * 
 * @author Mark Forjahn
 * 
 */
public class ApplicationRegistry {
	private HashSet<Application> applications = new HashSet<Application>();

	public void addApplication(Application application) {
		applications.add(application);
	}

	/**
	 * Return the application of an aid
	 * 
	 * @param aid
	 *            the application's aid
	 * @param state
	 *            actual state
	 * @return application to given aid
	 * @throws AIDNotFoundException
	 */
	public Application getApplication(byte[] aid,
			LogState state) throws AIDNotFoundException {
		for (Application application : applications) {
			if (HelperClass.toHexString(
					application.getAID()).equals(
					HelperClass.toHexString(aid))) {
				return application;
			}
		}
		throw new AIDNotFoundException(
				"no application found that matches aid "
						+ HelperClass.toHexString(aid),
				state);
	}

	/**
	 * 
	 * @return all available applications
	 */
	public Object[] getAllApplications() {
		return this.applications.toArray();
	}

}
