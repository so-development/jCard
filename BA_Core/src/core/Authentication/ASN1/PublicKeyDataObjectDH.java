package core.Authentication.ASN1;

import java.io.IOException;
import java.math.BigInteger;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.crypto.params.DHParameters;

import core.Exceptions.PACERuntimeException;

/**
 * This class represents a specific Diffie Hellman Public Key.
 * 
 * Data Object				Abbrev.		Tag		Type
 * Object Identifier					0x06	Object Identifier
 * Prime modulus			p			0x81	Unsigned Integer
 * Order of the subgroup	q			0x82	Unsigned Integer
 * Generator				g			0x83	Unsigned Integer
 * Public value				y			0x84	Unsigned Integer
 * 
 * 
 * @author Mark Forjahn
 * 
 */
@SuppressWarnings("deprecation")
public class PublicKeyDataObjectDH extends PublicKeyDataObject implements
		DHPublicKey {

	private static final long serialVersionUID = -2429876553550575230L;
	private DERTaggedObject p = null;
	private DERTaggedObject g = null;
	private DERTaggedObject q = null;
	private DERTaggedObject y = null;

	/**
	 * @param oid
	 *            see {@link PACEObjectIdentifiers}
	 * @param data
	 *            received bytes
	 */
	public PublicKeyDataObjectDH(DERObjectIdentifier oid, byte[] data) {
		super(oid);

		DERApplicationSpecific das = null;
		ASN1Sequence seq = null;

		try {
			das = (DERApplicationSpecific) DERApplicationSpecific
					.fromByteArray(data);
			seq = ASN1Sequence.getInstance(das.getObject(DERTags.SEQUENCE));
		} catch (IOException e) {
		}

		p = (DERTaggedObject) seq.getObjectAt(1);
		q = (DERTaggedObject) seq.getObjectAt(2);
		g = (DERTaggedObject) seq.getObjectAt(3);
		y = (DERTaggedObject) seq.getObjectAt(4);
	}

	/**
	 * @param oid
	 *            see {@link PACEObjectIdentifiers}
	 * @param dhParams
	 *            domain parameter
	 * @param y
	 *            public value
	 */
	public PublicKeyDataObjectDH(DERObjectIdentifier oid,
			DHParameters dhParams, BigInteger y) {
		super(oid);
		this.p = new DERTaggedObject(0x81, new DERInteger(dhParams.getP()));
		this.q = new DERTaggedObject(0x82, new DERInteger(dhParams.getQ()));
		this.g = new DERTaggedObject(0x83, new DERInteger(dhParams.getG()));
		this.y = new DERTaggedObject(0x84, new DERInteger(y));
		vector.add(this.p);
		vector.add(this.q);
		vector.add(this.g);
		vector.add(this.y);
	}

	@Override
	public DHParameterSpec getParams() {
		DERInteger derInt_p = (DERInteger) p.getObjectParser(DERTags.INTEGER,
				true);
		DERInteger derInt_g = (DERInteger) g.getObjectParser(DERTags.INTEGER,
				true);

		return new DHParameterSpec(derInt_p.getValue(), derInt_g.getValue());
	}

	@Override
	public String getAlgorithm() {
		return "DH";
	}

	@Override
	public byte[] getEncoded() {
		try {
			return super.getDEREncoded();
		} catch (PACERuntimeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	/**
	 * Public value/ key
	 */
	public BigInteger getY() {
		DERInteger derInt = (DERInteger) y.getObjectParser(DERTags.INTEGER,
				true);
		return derInt.getPositiveValue();
	}
}
