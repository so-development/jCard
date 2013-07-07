package Management;

import core.Authentication.PACE.Algorithms;
import core.Management.PACEProtocol_Settings;

/**
 * Contains information for PACE Protocol which are set while runtime
 * 
 * @author Mark Forjahn
 * 
 */
public class PICCPACEProtocol_Settings extends
		PACEProtocol_Settings {

	private int standardizedDomainParameterID; // user can chose id
	private Algorithms algorithm; // user can chose algorithm

	public int getStandardizedDomainParameterID() {
		return standardizedDomainParameterID;
	}

	public void setStandardizedDomainParameterID(int id) {
		this.standardizedDomainParameterID = id;
	}

	public Algorithms getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(Algorithms algorithm) {
		this.algorithm = algorithm;
	}

}
