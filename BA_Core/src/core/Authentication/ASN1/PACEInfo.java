package core.Authentication.ASN1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERTags;

/**
 * This class represents the PACEInfo structure.
 * 
 * PaceInfo ::= SEQUENCE {
 *      protocol	OBJECT IDENTIFIER(
 *					id-PACE-DH-GM-3DES-CBC-CBC 			
 *					id-PACE-DH-GM-AES-CBC-CMAC-128 		
 *					id-PACE-DH-GM-AES-CBC-CMAC-192 		
 *					id-PACE-DH-GM-AES-CBC-CMAC-256 		
 *					id-PACE-ECDH-GM-3DES-CBC-CBC 		
 *					id-PACE-ECDH-GM-AES-CBC-CMAC-128 
 *					id-PACE-ECDH-GM-AES-CBC-CMAC-192 
 *					id-PACE-ECDH-GM-AES-CBC-CMAC-256),
 *      version		INTEGER, -- SHOULD be 2
 *      parameterId	INTEGER OPTIONAL
 * }
 * 
 * @author Mark Forjahn
 */

@SuppressWarnings("deprecation")
public class PACEInfo {

	private DERObjectIdentifier protocol; // OID {@link PACEObjectIdentifiers}
	private DERInteger version; // Version - should be 2
	private DERInteger parameterId; // id of the standardized domain parameter

	/**
	 * Constructor for PCD.
	 * 
	 * @param data
	 *            byte array that was transmitted from PICC to PCD
	 * @throws IOException
	 */
	public PACEInfo(byte[] data) throws IOException {
		protocol = null;
		version = null;
		parameterId = null;

		DERApplicationSpecific das = null;
		ASN1Sequence seq = null;

		das = (DERApplicationSpecific) DERApplicationSpecific
				.fromByteArray(data);
		seq = ASN1Sequence.getInstance(das.getObject(DERTags.SEQUENCE));

		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		version = (DERInteger) seq.getObjectAt(1);
		parameterId = (DERInteger) seq.getObjectAt(2);
	}

	/**
	 * Constructor for PICC
	 * 
	 * @param oid
	 *            {@link PACEObjectIdentifiers}
	 * @param version
	 *            PACE version -> always gets value "2"
	 * @param parameterId
	 *            id of standardized domain parameter
	 */
	public PACEInfo(DERObjectIdentifier oid, int version, int parameterId) {
		this.protocol = oid;
		this.version = new DERInteger(version);
		this.parameterId = new DERInteger(parameterId);
	}

	public byte[] getDEREncoded() throws IOException {
		ASN1EncodableVector derEnc = new ASN1EncodableVector();
		derEnc.add(protocol);
		derEnc.add(version);
		derEnc.add(parameterId);

		return new DERApplicationSpecific(0x00, derEnc).getEncoded();
	}

	public String getProtocolOID() {
		return protocol.toString();
	}

	public Integer getVersion() {
		return version.getValue().intValue();
	}

	public Integer getParameterId() {
		return parameterId.getValue().intValue();
	}
}