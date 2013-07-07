package core.Support;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

/**
 * This class contains converting and helper methods.
 * 
 * @author Mark Forjahn
 */
public class HelperClass {

	/**
	 * Converts a byte into an integer
	 * 
	 * @param b
	 *            byte to convert
	 * @return integer-value
	 */
	public static int byteToInt(byte b) {
		return b & 0xff;
	}

	/**
	 * Converts a byte array into a hexadecimal string
	 * 
	 * @param b
	 *            bytes to convert
	 * @return hexadecimal output
	 */
	public static String toHexString(byte b[]) {
		String ret = "";
		if (b != null) {
			for (int i = 0; i < b.length; i++) {
				ret += toHexString(b[i]);
			}
		}
		return ret;
	}

	/**
	 * Converts a byte into a hexadecimal string
	 * 
	 * @param b
	 *            byte to convert
	 * @return hexadecimal output
	 */
	public static String toHexString(byte b) {
		int value = (b & 0x7F) + (b < 0 ? 128 : 0);
		String ret = (value < 16 ? "0" : "");
		ret += Integer.toHexString(value).toUpperCase();
		return ret;
	}

	/**
	 * Converts a BigInteger into a byte array. Zeros in front are cut off. (a
	 * BigInteger has a zero-byte in front in case of a positive value)
	 * 
	 * @param bi
	 *            value to convert
	 * @return byte-array without zero-byte in front
	 */
	public static byte[] bigIntToByteArray(BigInteger bi) {
		byte[] temp = bi.toByteArray();
		byte[] returnbytes = null;
		if (temp[0] == 0) {
			returnbytes = new byte[temp.length - 1];
			System.arraycopy(temp, 1, returnbytes, 0,
					returnbytes.length);
			return returnbytes;
		} else
			return temp;
	}

	/**
	 * Converts byte array into a positiv(!) BigInteger value
	 * 
	 * @param b
	 *            bytes to convert
	 * @return positiv BigIntger value
	 */
	public static BigInteger byteArrayToBigInteger(byte[] b) {
		return new BigInteger(1, b);
	}

	/**
	 * Converts bytes to an ECPoint on a given curve. Prime field p will be
	 * adopted of given curve.
	 * 
	 * @param curve
	 *            curve, that contains the point
	 * @return point on curve
	 */
	public static ECPoint bytesToECPoint(byte[] bytes,
			ECCurve.Fp curve) {
		byte[] x = new byte[(bytes.length - 1) / 2];
		byte[] y = new byte[(bytes.length - 1) / 2];

		System.arraycopy(bytes, 1, x, 0,
				(bytes.length - 1) / 2);
		System.arraycopy(bytes,
				1 + ((bytes.length - 1) / 2), y, 0,
				(bytes.length - 1) / 2);
		ECFieldElement.Fp q_x = new ECFieldElement.Fp(
				curve.getQ(), new BigInteger(1, x));
		ECFieldElement.Fp q_y = new ECFieldElement.Fp(
				curve.getQ(), new BigInteger(1, y));
		ECPoint point = new ECPoint.Fp(curve, q_x, q_y);
		return point;
	}

	/**
	 * Concatenates two byte arrays
	 * 
	 * @param a
	 *            first array
	 * @param b
	 *            second array
	 * @return concatenation of a and b (a || b)
	 */
	public static byte[] concatenateByteArrays(byte[] a,
			byte[] b) {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);

		return c;
	}

	/**
	 * Concatenates x byte arrays
	 * 
	 * @param a
	 *            byte arrays
	 * @return concatenation of a all arrays existing in a
	 */
	public static byte[] concatenateByteArrays(byte[][] a) {
		byte ret[] = null;
		for (int i = 0; i < a.length; i++) {
			if (i == 0) {
				ret = a[i];
			} else {
				ret = concatenateByteArrays(ret, a[i]);
			}
		}

		return ret;
	}

	/**
	 * Converts an int to a byte array
	 * 
	 * @param i
	 *            value to convert
	 * @return byte array of int value
	 */
	public static byte[] intToByteArray(int i) {
		ByteBuffer buffer = ByteBuffer.allocate(4); // int size: 32 bit -> 4
													// byte
		buffer.putInt(i);
		return buffer.array();
	}

}
