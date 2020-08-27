package rmidemo.rmiserver;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;

import javax.crypto.KeyAgreement;

import java.util.*;
import java.nio.ByteBuffer;
import java.io.Console;


public class ecdh {

  public static void main(String[] args) throws Exception {
    Console console = System.console();
    // Generate ephemeral ECDH keypair
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(128);
    KeyPair kp = kpg.generateKeyPair();
    byte[] ourPk = kp.getPublic().getEncoded();

    // Display our public key
    //console.printf("Public Key: %s%n", printHexBinary(ourPk));

    // Read other's public key:
    byte[] otherPk =  kp.getPublic().getEncoded();

    KeyFactory kf = KeyFactory.getInstance("EC");
    X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
    PublicKey otherPublicKey = kf.generatePublic(pkSpec);

    // Perform key agreement
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    ka.init(kp.getPrivate());
    ka.doPhase(otherPublicKey, true);

    // Read shared secret
    byte[] sharedSecret = ka.generateSecret();
    //console.printf("Shared secret: %s%n", printHexBinary(sharedSecret));

    // Derive a key from the shared secret and both public keys
    MessageDigest hash = MessageDigest.getInstance("SHA-256");
    hash.update(sharedSecret);
    // Simple deterministic ordering
    List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(otherPk));
    Collections.sort(keys);
    hash.update(keys.get(0));
    hash.update(keys.get(1));

    byte[] derivedKey = hash.digest();
    //console.printf("Final key: %s%n", printHexBinary(derivedKey));
  }
}