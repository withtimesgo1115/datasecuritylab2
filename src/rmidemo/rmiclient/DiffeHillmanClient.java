package rmidemo.rmiclient;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class DiffeHillmanClient {

	private static byte[] alicePubKeyEnc;
	private static byte[] bobPubKeyEnc;
	private static KeyAgreement aliceKeyAgree;
	private static byte[] aliceSharedSecret ;
	private static byte[] ciphertext;
	private static byte[] encodedParams;
	private static Cipher bobCipher;
	public void DiffeHillmenInit()  throws IOException, RemoteException, Exception{
        /*
         * Alice creates her own DH key pair with 2048-bit key size
         */
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("EC");
        aliceKpairGen.initialize(128);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
        
        // Alice creates and initializes her DH KeyAgreement object
        System.out.println("ALICE: Initialization ...");
        aliceKeyAgree = KeyAgreement.getInstance("ECDH");
        aliceKeyAgree.init(aliceKpair.getPrivate());
        
        // Alice encodes her public key, and sends it over to Bob.
         setAlicePubKeyEnc(aliceKpair.getPublic().getEncoded());

    
	}
	
	public void generateSharedSecret() throws Exception {
		 /*
         * Alice uses Bob's public key for the first (and only) phase
         * of her version of the DH
         * protocol.
         * Before she can do so, she has to instantiate a DH public key
         * from Bob's encoded key material.
         */
        KeyFactory aliceKeyFac = KeyFactory.getInstance("EC");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(getBobPubKeyEnc());
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
        System.out.println("ALICE: Execute PHASE1 ...");
        aliceKeyAgree.doPhase(bobPubKey, true);
        /*
         * At this stage, both Alice and Bob have completed the DH key
         * agreement protocol.
         * Both generate the (same) shared secret.
         */
        
        
        aliceSharedSecret = aliceKeyAgree.generateSecret();
        System.out.println("Alice secret: " +
                toHexString(aliceSharedSecret));
	}

	public void initSymmetricConnection() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
	IllegalBlockSizeException, BadPaddingException, IOException {
/*
 * Now let's create a SecretKey object using the shared secret
 * and use it for encryption. First, we generate SecretKeys for the
 * "AES" algorithm (based on the raw shared secret data) and
 * Then we use AES in CBC mode, which requires an initialization
 * vector (IV) parameter. Note that you have to use the same IV
 * for encryption and decryption: If you use a different IV for
 * decryption than you used for encryption, decryption will fail.
 *
 * If you do not specify an IV when you initialize the Cipher
 * object for encryption, the underlying implementation will generate
 * a random one, which you have to retrieve using the
 * javax.crypto.Cipher.getParameters() method, which returns an
 * instance of java.security.AlgorithmParameters. You need to transfer
 * the contents of that object (e.g., in encoded format, obtained via
 * the AlgorithmParameters.getEncoded() method) to the party who will
 * do the decryption. When initializing the Cipher for decryption,
 * the (reinstantiated) AlgorithmParameters object must be explicitly
 * passed to the Cipher.init() method.
 */
System.out.println("Use shared secret as SecretKey object ...");
SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");

/*
 * Bob encrypts, using AES in CBC mode
 */
bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
bobCipher.init(Cipher.ENCRYPT_MODE, aliceAesKey);
byte[] cleartext = "This is just an example".getBytes();
 //

// Retrieve the parameter that was used, and transfer it to Alice in
// encoded format
setEncodedParams(bobCipher.getParameters().getEncoded());
}
	public byte[] doSymmetricEncryption(String clearData) throws IllegalBlockSizeException, BadPaddingException {
		 setCiphertext(bobCipher.doFinal(clearData.getBytes()));
		 return ciphertext;
	}  /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }

	public static byte[] getAlicePubKeyEnc() {
		return alicePubKeyEnc;
	}

	public static void setAlicePubKeyEnc(byte[] alicePubKeyEnc) {
		DiffeHillmanClient.alicePubKeyEnc = alicePubKeyEnc;
	}

	public static byte[] getBobPubKeyEnc() {
		return bobPubKeyEnc;
	}

	public static void setBobPubKeyEnc(byte[] bobPubKeyEnc) {
		DiffeHillmanClient.bobPubKeyEnc = bobPubKeyEnc;
	}

	public static byte[] getEncodedParams() {
		return encodedParams;
	}

	public static void setEncodedParams(byte[] encodedParams) {
		DiffeHillmanClient.encodedParams = encodedParams;
	}

	public static byte[] getCiphertext() {
		return ciphertext;
	}

	public static void setCiphertext(byte[] ciphertext) {
		DiffeHillmanClient.ciphertext = ciphertext;
	}
}
