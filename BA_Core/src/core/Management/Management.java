package core.Management;

import core.Application.Application;

/**
 * Contains all applications as well as additional settings
 * 
 * @author Mark Forjahn
 * 
 */
public class Management {
	private Settings settings;
	private ApplicationRegistry applicationRegistry;

	public Management() {
		this.settings = new Settings();
		this.applicationRegistry = new ApplicationRegistry();
	}

	public void setAuthenticationProtocol(
			PACEProtocol_Settings authProt) {
		this.settings.setAuthenticationProtocol(authProt);
	}

	public Settings getSettings() {
		return this.settings;
	}

	public void addApplication(Application application) {
		applicationRegistry.addApplication(application);
	}

	public ApplicationRegistry getApplicationRegistry() {
		return applicationRegistry;
	}

}
