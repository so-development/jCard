package core.Authentication.PACE;

import java.math.BigInteger;

import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import core.Exceptions.PACERuntimeException;
import core.Logging.LogState;

/**
 * This class contains either DH parameters or EC parameters. It's initialized
 * by the specific id.
 * 
 * Standardized domain parameter:
 * 
 * 	ID	Name													Size		Type
 * 	0	1024-bit MODP Group with 160-bit Prime Order Subgroup	1024/160	DH
 *	1	2048-bit MODP Group with 224-bit Prime Order Subgroup	2048/224	DH
 * 	2	2048-bit MODP Group with 256-bit Prime Order Subgroup	2048/256	DH
 *	8	NIST P-192 (secp192r1)									192			EC
 *	9	BrainpoolP192r1											192			EC
 *	10	NIST P-224 (secp224r1)									224			EC
 *	11	BrainpoolP224r1											224			EC
 *	12	NIST P-256 (secp256r1)									256			EC
 *	13	BrainpoolP256r1											256			EC
 *	14	BrainpoolP320r1											320			EC
 *	15	NIST P-384 (secp384r1)									384			EC
 *	16	BrainpoolP384r1											384			EC
 *	17	BrainpoolP512r1											512			EC
 *	18	NIST P-521 (secp521r1)									521			EC
 * 
 * @author Mark Forjahn
 * 
 */
public class DomainParameter {

	private DHParameters dhParameters = null; // DH parameters
	private ECParameterSpec ecSpec = null; // EC parameters
	private DPTypes type = null; // DH or EC
	private int id; // id of standardized domain parameter

	public DomainParameter(int id) throws PACERuntimeException {
		if (id >= 0 && id <= 18) {
			this.id = id;
			switch (id) {
			case 0:
				dhParameters = DHStandardizedDomainParameters.modp1024_160();
				type = DPTypes.DH;
				break;
			case 1:
				dhParameters = DHStandardizedDomainParameters.modp2048_224();
				type = DPTypes.DH;
				break;
			case 2:
				dhParameters = DHStandardizedDomainParameters.modp2048_256();
				type = DPTypes.DH;
				break;
			case 8:
				ecSpec = ECNamedCurveTable.getParameterSpec("secp192r1");
				type = DPTypes.ECDH;
				break;
			case 9:
				ecSpec = ECNamedCurveTable.getParameterSpec("secp192r1");
				type = DPTypes.ECDH;
				break;
			case 10:
				;
				ecSpec = ECNamedCurveTable.getParameterSpec("secp224r1");
				type = DPTypes.ECDH;
				break;
			case 11:
				ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp224r1");
				type = DPTypes.ECDH;
				break;
			case 12:
				ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
				type = DPTypes.ECDH;
				break;
			case 13:
				ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
				type = DPTypes.ECDH;
				break;
			case 14:
				ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp320r1");
				type = DPTypes.ECDH;
				break;
			case 15:
				ecSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
				type = DPTypes.ECDH;
				break;
			case 16:
				ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp384r1");
				type = DPTypes.ECDH;
				break;
			case 17:
				ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp512r1");
				type = DPTypes.ECDH;
				break;
			case 18:
				ecSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
				type = DPTypes.ECDH;
				break;
			}
		} else {
			throw new PACERuntimeException(
					"ID for standardized domain parameter not valid!",
					LogState.AUTHENTICATE);
		}
	}

	public void setNewG(BigInteger newG) {
		dhParameters = new DHParameters(dhParameters.getP(), newG,
				dhParameters.getQ());
	}

	public void setNewG(ECPoint newG) {
		ecSpec = new ECParameterSpec(ecSpec.getCurve(), newG, ecSpec.getN(),
				ecSpec.getH());
	}

	public DPTypes getType() {
		return this.type;
	}

	public ECParameterSpec getECParameter() {
		return ecSpec;
	}

	public DHParameters getDHParameter() {
		return dhParameters;
	}

	public int getId() {
		return id;
	}

}
