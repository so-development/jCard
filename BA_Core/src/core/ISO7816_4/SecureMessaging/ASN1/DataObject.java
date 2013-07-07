package core.ISO7816_4.SecureMessaging.ASN1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * DO87, DO97, DO99, DO8E
 * 
 * @author Mark Forjahn
 * 
 */
public class DataObject {

	public static byte[] convertBytesToDER(byte[] data,
			int tagno) throws IOException {
		DERTaggedObject der = new DERTaggedObject(tagno,
				new DEROctetString(data));
		return der.getEncoded();
	}

	public static byte[] convertBytesToDER(byte data,
			int tagno) throws IOException {
		byte[] bytes = new byte[1];
		bytes[0] = data;

		return convertBytesToDER(bytes, tagno);
	}

	public static byte[] convertDERToBytes(byte[] data)
			throws IOException {
		ASN1InputStream asn1 = new ASN1InputStream(data);
		DERTaggedObject der = null;
		byte[] returnData = null;

		der = (DERTaggedObject) asn1.readObject();
		DEROctetString ocs = (DEROctetString) der
				.getObject();
		returnData = ocs.getOctets();
		asn1.close();

		return returnData;
	}

	public static int getTagno(byte[] data)
			throws IOException {
		ASN1InputStream asn1 = new ASN1InputStream(data);
		DERTaggedObject der = null;

		der = (DERTaggedObject) asn1.readObject();
		asn1.close();

		return der.getTagNo();
	}
}
