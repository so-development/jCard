package core.Authentication.ASN1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERTaggedObject;

import core.Exceptions.PACERuntimeException;
import core.Logging.LogState;

/**
 * This class represents a public key data object. In any case (Diffie Hellman
 * Public Keys or Elliptic Curve Public Keys) there is a object identifier
 * needed. Child classes are: {@link PublicKeyDataObjectDH} and
 * {@link PublicKeyDataObjectEC}
 * 
 * @author Mark Forjahn
 * 
 */
public abstract class PublicKeyDataObject {

	private DERObjectIdentifier tag_06 
		= null; // Object identifier which contains oid of algorithm
				// which is used
	protected ASN1EncodableVector vector 
		= new ASN1EncodableVector(); // Contains all data objects
									//of the specific public key

	/**
	 * Is called by constructor of child class
	 * 
	 * @param oid
	 *            see {@link PACEObjectIdentifiers}
	 */
	public PublicKeyDataObject(DERObjectIdentifier oid) {
		tag_06 = oid;
		vector.add(new DERTaggedObject(0x06, tag_06));
	}

	/**
	 * 
	 * @return Used algorithm oid; see {@link PACEObjectIdentifiers}
	 */
	public String getOID() {
		return tag_06.toString();
	}

	public byte[] getDEREncoded() throws PACERuntimeException {
		try {
			return new DERApplicationSpecific(0x7C, vector).getEncoded();
		} catch (IOException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		}
	}

}
