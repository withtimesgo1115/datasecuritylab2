package rmidemo.rmiserver;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DiffeHillmanServer {
	 private byte[] bobSharedSecret ;
	 private byte[] encodedParams;
	 private Cipher aliceCipher;
	 public byte[] getBobSharedSecret() {
		return bobSharedSecret;
	}
	public void DiffeHillmanServer() {
		
	}
	public void setBobSharedSecret(byte[] bobSharedSecret) {
		this.bobSharedSecret = bobSharedSecret;
	}
	public byte[] init(byte[] alicePubKeyEnc) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException {
		
        /*
         * Let's turn over to Bob. Bob has received Alice's public key
         * in encoded format.
         * He instantiates a DH public key from the encoded key material.
         */
        KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
        
        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

        /*
         * Bob gets the DH parameters associated with Alice's public key.
         * He must use the same parameters when he generates his own key
         * pair.
         */
        DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey)alicePubKey).getParams();

        // Bob creates his own DH key pair
        System.out.println("BOB: Generate DH keypair ...");
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamFromAlicePubKey);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();

        // Bob creates and initializes his DH KeyAgreement object
        System.out.println("BOB: Initialization ...");
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());

        // Bob encodes his public key, and sends it over to Alice.
        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();
        
        /*
         * Bob uses Alice's public key for the first (and only) phase
         * of his version of the DH
         * protocol.
         */
        System.out.println("BOB: Execute PHASE1 ...");
        bobKeyAgree.doPhase(alicePubKey, true);
        /*
         * At this stage, both Alice and Bob have completed the DH key
         * agreement protocol.
         * Both generate the (same) shared secret.
         */
        
        
        bobSharedSecret = bobKeyAgree.generateSecret();
        // provide output buffer of required size
        System.out.println("bob secret: " +
                toHexString(bobSharedSecret));
        return bobPubKeyEnc;
	}
	public void initSymmetricConnection() throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		/*
         * Alice decrypts, using AES in CBC mode
         */
    	SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
        
        /*
         * Alice decrypts, using AES in CBC mode
         */
        AlgorithmParameters aesParams = null;
        // Instantiate AlgorithmParameters object from parameter encoding
        // obtained from Bob
        aesParams = AlgorithmParameters.getInstance("AES");
        try {
			aesParams.init(getEncodedParams());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aliceCipher.init(Cipher.DECRYPT_MODE, bobAesKey, aesParams);
	}
	
	public String doSymmetricEncryption(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {
        byte[] recovered = aliceCipher.doFinal(ciphertext);
        //byte[] cleartext1 = "vv".getBytes("UTF-8");
        //String str = new String(cleartext1);
        String retrivemessage = new String(recovered);
        //if (!java.util.Arrays.equals(cleartext1, recovered)) throw new Exception("AES in CBC mode recovered text is different from cleartext");
        System.out.println("AES in CBC mode recovered text is " + retrivemessage );
        
        return retrivemessage;
	}
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

	public byte[] getEncodedParams() {
		return encodedParams;
	}

	public void setEncodedParams(byte[] encodedParams) {
		this.encodedParams = encodedParams;
	}
}
