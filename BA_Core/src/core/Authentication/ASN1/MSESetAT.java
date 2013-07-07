package core.Authentication.ASN1;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERTags;

import core.Authentication.PACE.PasswordTypes;

/**
 * This class represents the "MSE:Set AT" structure
 * 
 * @author Mark Forjahn
 * 
 */
@SuppressWarnings("deprecation")
public class MSESetAT {

	private DERTaggedObject mse_Tag_80 = null; // OID to use; {@link
												// PACEObjectIdentifiers}
	private DERTaggedObject mse_Tag_83 = null; // secret key to use (0x02: CAN,
												// 0x03: PIN)
	private DERTaggedObject mse_Tag_84 = null; // standardized domain parameter
												// to use

	/**
	 * Constructor for PICC.
	 * 
	 * @param data
	 *            Transmitted bytes from PCD to PICC
	 * @throws IOException
	 */
	public MSESetAT(byte[] data) throws IOException {

		DERApplicationSpecific das = null;
		ASN1Sequence seq = null;

		das = (DERApplicationSpecific) DERApplicationSpecific
				.fromByteArray(data);
		seq = ASN1Sequence.getInstance(das.getObject(DERTags.SEQUENCE));

		mse_Tag_80 = (DERTaggedObject) seq.getObjectAt(0);
		mse_Tag_83 = (DERTaggedObject) seq.getObjectAt(1);
		mse_Tag_84 = (DERTaggedObject) seq.getObjectAt(2);
	}

	/**
	 * Constructor for PCD.
	 * 
	 * @param protocolOID
	 *            OID to use; {@link PACEObjectIdentifiers}
	 * @param parameterId
	 *            standardized domain parameter to use
	 * @param type
	 *            type of shared secret to use as pi. PIN and CAN possible here.
	 */
	public MSESetAT(DERObjectIdentifier protocolOID, int parameterId,
			PasswordTypes type) {
		mse_Tag_80 = new DERTaggedObject(0x80, protocolOID);

		if (type.equals(PasswordTypes.CAN)) {
			mse_Tag_83 = new DERTaggedObject(0x83, new DERInteger(2));
		} else {
			mse_Tag_83 = new DERTaggedObject(0x83, new DERInteger(3));
		}

		mse_Tag_84 = new DERTaggedObject(0x84, new DERInteger(parameterId));
	}

	public PasswordTypes getSharedKey() {
		DERInteger derInt = (DERInteger) mse_Tag_83.getObjectParser(
				DERTags.INTEGER, true);
		if (derInt.getValue().equals(BigInteger.valueOf(2))) {
			return PasswordTypes.CAN;
		} else if (derInt.getValue().equals(BigInteger.valueOf(3))) {
			return PasswordTypes.PIN;
		}
		return null;
	}

	public DERObjectIdentifier getProtocolOID() {
		DERObjectIdentifier oid = (DERObjectIdentifier) mse_Tag_80
				.getObjectParser(DERTags.OBJECT_IDENTIFIER, true);
		return oid;
	}

	public int getParameterId() {
		DERInteger derInt = (DERInteger) mse_Tag_84.getObjectParser(
				DERTags.INTEGER, true);
		return derInt.getValue().intValue();
	}

	public byte[] getDEREncoded() throws IOException {
		ASN1EncodableVector asn1vec = new ASN1EncodableVector();
		asn1vec.add(mse_Tag_80);
		asn1vec.add(mse_Tag_83);
		asn1vec.add(mse_Tag_84);
		return new DERApplicationSpecific(0x00, asn1vec).getEncoded();
	}

}
