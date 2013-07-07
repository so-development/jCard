package core.Authentication.ASN1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERTags;

import core.Exceptions.PACERuntimeException;

/**
 * Encodes/decodes ASN1-structures for dynamic authentication data in PACE. Only
 * one DERTaggedObject in one ASN1Sequence is possible here, because there's no
 * need to be able to handle more objects in one sequence for General
 * Authentication messages in PACE.
 * 
 * @author Mark Forjahn
 * 
 */
@SuppressWarnings("deprecation")
public class DynamicAuthenticationData {

	/**
	 * @param tagno
	 *            Tag number of data, that should be read
	 * @param data
	 *            data in DER-structure
	 * @return "plaintext" data of tag number
	 * @throws PACERuntimeException
	 * @throws IOException
	 */
	public static byte[] convertDERToBytes(int tagno,
			byte[] data) throws PACERuntimeException,
			IOException {
		DERApplicationSpecific das = null;
		ASN1Sequence seq = null;

		das = (DERApplicationSpecific) DERApplicationSpecific
				.fromByteArray(data);
		seq = ASN1Sequence.getInstance(das
				.getObject(DERTags.SEQUENCE));

		// read every entry, until a DERTaggedObject with tag number "tagno" is
		// found and give it back
		for (int i = 0; i < seq.size(); i++) {
			DERTaggedObject temp = (DERTaggedObject) seq
					.getObjectAt(i);
			if (temp.getTagNo() == tagno) {
				return getDataObject(temp);
			}
		}
		return null;
	}

	/**
	 * Converts bytes into the DER-structure
	 * 
	 * @param tagno
	 *            tag number of object
	 * @param data
	 *            bytes that need to be converted
	 * @return bytes in DER-structure
	 * @throws IOException
	 */
	public static byte[] convertBytesToDER(int tagno,
			byte[] data) throws IOException {
		return getDEREncoded(new DERTaggedObject(false,
				tagno, new DEROctetString(data)));
	}

	/**
	 * Called by "convertDERToBytes(..) to receive bytes"
	 * 
	 * @param obj
	 *            object that contains the data
	 * @return converted bytes
	 */
	private static byte[] getDataObject(DERTaggedObject obj) {
		DEROctetString octetString = (DEROctetString) obj
				.getObjectParser(DERTags.OCTET_STRING,
						false);
		return octetString.getOctets();
	}

	/**
	 * Called by
	 * "convertBytesToDER(..) insert TaggedObject into to ASN1EncodableVector and then into DERApplicationSpecific"
	 * 
	 * @param obj
	 *            object that contains the data
	 * @return bytes of DERApplicationSpecific object
	 */
	private static byte[] getDEREncoded(DERTaggedObject obj)
			throws IOException {
		ASN1EncodableVector asn1vec = new ASN1EncodableVector();
		asn1vec.add(obj);

		return new DERApplicationSpecific(0x7C, asn1vec)
				.getEncoded();
	}

}
