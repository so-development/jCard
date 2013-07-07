package core.Authentication.ASN1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import core.Exceptions.PACERuntimeException;
import core.Support.HelperClass;

/**
 * This class represents a specific Elliptic Curve Public Key
 * 
 * Data Object Abbrev. Tag Type Object Identifier 0x06 Object Identifier Prime
 * modulus p 0x81 Unsigned Integer First coefficient a 0x82 Unsigned Integer
 * Second coefficient b 0x83 Unsigned Integer Base point G 0x84 Elliptic Curve
 * Point Order of the base point r 0x85 Unsigned Integer Public point Y 0x86
 * Elliptic Curve Point Cofactor f 0x87 Unsigned Integer
 * 
 * 
 * @author Mark Forjahn
 * 
 */
@SuppressWarnings("deprecation")
public class PublicKeyDataObjectEC extends PublicKeyDataObject
		implements ECPublicKey {

	private static final long serialVersionUID = 1652780028643853484L;

	private DERTaggedObject p = null; // = q
	private DERTaggedObject a = null;
	private DERTaggedObject b = null;
	private DERTaggedObject G = null;
	private DERTaggedObject r = null;
	private DERTaggedObject Y = null;
	private DERTaggedObject f = null;

	public PublicKeyDataObjectEC(DERObjectIdentifier oid, byte[] data) {
		super(oid);

		DERApplicationSpecific das = null;
		ASN1Sequence seq = null;

		try {
			das = (DERApplicationSpecific) DERApplicationSpecific
					.fromByteArray(data);
			seq = ASN1Sequence.getInstance(das
					.getObject(DERTags.SEQUENCE));
		} catch (IOException e) {
		}

		p = (DERTaggedObject) seq.getObjectAt(1);
		a = (DERTaggedObject) seq.getObjectAt(2);
		b = (DERTaggedObject) seq.getObjectAt(3);
		G = (DERTaggedObject) seq.getObjectAt(4);
		r = (DERTaggedObject) seq.getObjectAt(5);
		Y = (DERTaggedObject) seq.getObjectAt(6);
		f = (DERTaggedObject) seq.getObjectAt(7);
	}

	public PublicKeyDataObjectEC(DERObjectIdentifier oid,
			ECParameterSpec ecParamSpec, ECPoint Y) {
		super(oid);
		this.p = new DERTaggedObject(0x81, new DERInteger(
				((ECCurve.Fp) Y.getCurve()).getQ()));
		this.a = new DERTaggedObject(0x82, new DERInteger(ecParamSpec
				.getCurve().getA().toBigInteger()));
		this.b = new DERTaggedObject(0x83, new DERInteger(ecParamSpec
				.getCurve().getB().toBigInteger()));
		this.G = new DERTaggedObject(0x84, new DEROctetString(
				ecParamSpec.getG().getEncoded()));
		this.r = new DERTaggedObject(0x85, new DERInteger(
				ecParamSpec.getN()));
		this.Y = new DERTaggedObject(0x86, new DEROctetString(
				Y.getEncoded()));
		this.f = new DERTaggedObject(0x87, new DERInteger(
				ecParamSpec.getH()));
		vector.add(this.p);
		vector.add(this.a);
		vector.add(this.b);
		vector.add(this.G);
		vector.add(this.r);
		vector.add(this.Y);
		vector.add(this.f);
	}

	@Override
	public ECParameterSpec getParameters() {
		DERInteger derInt_p = (DERInteger) p.getObjectParser(
				DERTags.INTEGER, true);
		DERInteger derInt_a = (DERInteger) a.getObjectParser(
				DERTags.INTEGER, true);
		DERInteger derInt_b = (DERInteger) b.getObjectParser(
				DERTags.INTEGER, true);
		DEROctetString derInt_G = (DEROctetString) G.getObjectParser(
				DERTags.OCTET_STRING, true);
		DERInteger derInt_r = (DERInteger) r.getObjectParser(
				DERTags.INTEGER, true);
		DERInteger derInt_f = (DERInteger) f.getObjectParser(
				DERTags.INTEGER, true);

		ECCurve.Fp curve = new ECCurve.Fp(derInt_p.getValue(),
				derInt_a.getValue(), derInt_b.getValue());
		ECPoint pointG = HelperClass.bytesToECPoint(
				derInt_G.getOctets(), curve);
		ECParameterSpec ecParameterSpec = new ECParameterSpec(curve,
				pointG, derInt_r.getValue(), derInt_f.getValue());
		return ecParameterSpec;
	}

	@Override
	public String getAlgorithm() {
		return "EC";
	}

	@Override
	public byte[] getEncoded() {
		try {
			return super.getDEREncoded();
		} catch (PACERuntimeException e) {
		}
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	/**
	 *  Returns the public value/ point Y
	 */
	public ECPoint getQ() {

		// Read out all needed values
		DERInteger derInt_p = (DERInteger) p.getObjectParser(
				DERTags.INTEGER, true);
		DERInteger derInt_a = (DERInteger) a.getObjectParser(
				DERTags.INTEGER, true);
		DERInteger derInt_b = (DERInteger) b.getObjectParser(
				DERTags.INTEGER, true);
		DEROctetString derOstr_Y = (DEROctetString) DEROctetString
				.getInstance(Y, true);

		// Create curve and point
		ECCurve.Fp curve = new ECCurve.Fp(derInt_p.getValue(),
				derInt_a.getValue(), derInt_b.getValue());
		ECPoint point_Y = HelperClass.bytesToECPoint(
				derOstr_Y.getOctets(), curve);
		return point_Y;
	}
}
