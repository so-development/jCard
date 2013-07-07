package core.Authentication.ASN1;

import org.bouncycastle.asn1.DERObjectIdentifier;

/**
 * This class contains all in this project used protocol object identifier.
 * 
 * id-PACE-DH-GM 					OBJECT IDENTIFIER ::= {id-PACE 1}
 * id-PACE-DH-GM-3DES-CBC-CBC 		OBJECT IDENTIFIER ::= {id-PACE-DH-GM 1}
 * id-PACE-DH-GM-AES-CBC-CMAC-128 	OBJECT IDENTIFIER ::= {id-PACE-DH-GM 2}
 * id-PACE-DH-GM-AES-CBC-CMAC-192 	OBJECT IDENTIFIER ::= {id-PACE-DH-GM 3}
 * id-PACE-DH-GM-AES-CBC-CMAC-256 	OBJECT IDENTIFIER ::= {id-PACE-DH-GM 4}
 * id-PACE-ECDH-GM 					OBJECT IDENTIFIER ::= {id-PACE 2}
 * id-PACE-ECDH-GM-3DES-CBC-CBC 	OBJECT IDENTIFIER ::= {id-PACE-ECDH-GM 1}
 * id-PACE-ECDH-GM-AES-CBC-CMAC-128	OBJECT IDENTIFIER ::= {id-PACE-ECDH-GM 2}
 * id-PACE-ECDH-GM-AES-CBC-CMAC-192 OBJECT IDENTIFIER ::= {id-PACE-ECDH-GM 3}
 * id-PACE-ECDH-GM-AES-CBC-CMAC-256 OBJECT IDENTIFIER ::= {id-PACE-ECDH-GM 4}
 * 
 * @author Mark Forjahn
 * 
 */
public interface PACEObjectIdentifiers {

	public static final String id_BSI_PACE = new String(
			"0.4.0.127.0.7" + ".2.2.4");

	public static final DERObjectIdentifier id_PACE_DH_GM = new DERObjectIdentifier(
			id_BSI_PACE + ".1");
	public static final DERObjectIdentifier id_PACE_DH_GM_3DES_CBC_CBC = new DERObjectIdentifier(
			id_PACE_DH_GM + ".1");
	public static final DERObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_128 = new DERObjectIdentifier(
			id_PACE_DH_GM + ".2");
	public static final DERObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_192 = new DERObjectIdentifier(
			id_PACE_DH_GM + ".3");
	public static final DERObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_256 = new DERObjectIdentifier(
			id_PACE_DH_GM + ".4");

	public static final DERObjectIdentifier id_PACE_ECDH_GM = new DERObjectIdentifier(
			id_BSI_PACE + ".2");
	public static final DERObjectIdentifier id_PACE_ECDH_GM_3DES_CBC_CBC = new DERObjectIdentifier(
			id_PACE_ECDH_GM + ".1");
	public static final DERObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_128 = new DERObjectIdentifier(
			id_PACE_ECDH_GM + ".2");
	public static final DERObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_192 = new DERObjectIdentifier(
			id_PACE_ECDH_GM + ".3");
	public static final DERObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_256 = new DERObjectIdentifier(
			id_PACE_ECDH_GM + ".4");

}
