package opensc;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * RSA private key CRT component calculator based on code from http://rsaconverter.sourceforge.net/ 
 * 
 * @author Martin Paljak <martin@martinpaljak.net>
 *
 */
public class RSAKeyConverter {
	/**
	 * Calculates the Chinese Remainder Theorem components for a private key represented only with a modulus, private exponent and public exponent.
	 *
	 * @param n private modulus
	 * @param e public exponent
	 * @param d private modulus
	 * @return a {@link RSAPrivateCrtKey} object initiated with the right values.
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws UnrecoverableKeyException
	 */
	public static RSAPrivateCrtKey calculateCrtComponents(BigInteger n, BigInteger e, BigInteger d) throws NoSuchAlgorithmException, InvalidKeySpecException, UnrecoverableKeyException {
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		int counter = 100;
		
		BigInteger p = BigInteger.ZERO;
		BigInteger q = BigInteger.ZERO;
		BigInteger dp = BigInteger.ZERO;
		BigInteger dq = BigInteger.ZERO;
		BigInteger u = BigInteger.ZERO;
		
		BigInteger k = e.multiply(d);
		k = k.subtract(BigInteger.ONE);
		
		int t = 0;
		while (!k.testBit(t))
			t++;
		
		
		while (--counter > 0) {
			BigInteger kt = k;
			BigInteger g = BigInteger.probablePrime(n.bitCount(), sr);
			BigInteger gk = BigInteger.ZERO;
	
			int i = 0;
			
			for (i = 0; i < t; i++) {
				kt = kt.shiftRight(1);
				gk = g.modPow(kt, n);
				if (!gk.equals(BigInteger.ONE)) {
					BigInteger sq = gk.multiply(gk);
					if (sq.mod(n).equals(BigInteger.ONE))
						break;
				}
			}
			if (i < t) {
				gk = gk.subtract(BigInteger.ONE);
				p = gk.gcd(n);
				if (!p.equals(BigInteger.ONE))
					break;
			}
		}
		if (counter > 0) {
			q = n.divide(p);
			if (p.isProbablePrime(50) && q.isProbablePrime(50)) {
				if (q.compareTo(p) == 1) {
					BigInteger tmp = q;
					q = p;
					p = tmp;
				}
				
				dp = d.mod(p.subtract(BigInteger.ONE));
				dq = d.mod(q.subtract(BigInteger.ONE));
				u = q.modInverse(p);
				
				//done!
				RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, u);
				KeyFactory RSAKeyFactory = KeyFactory.getInstance("RSA");
				return (RSAPrivateCrtKey) RSAKeyFactory.generatePrivate(spec);
			}
			
		} 
		//RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
		throw new UnrecoverableKeyException("Could not derive CRT components!");
	}
	
	/**
	 * Tests if the key pair, consisting of a private and public (RSA) keys satisfies simple encryption-decryption test.
	 * 
	 * @param privkey {@link PrivateKey} of the keypair to be tested
	 * @param pubkey {@link PublicKey} of the keypair to be tested
	 * @return true if the keypair satisfies simple test, false or an exception otherwise.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private static boolean verifyKeypairIntegrity(RSAPrivateCrtKey privkey, RSAPublicKey pubkey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] nonce = new byte[16];
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");		
		Cipher verify_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
		sr.nextBytes(nonce);
		verify_cipher.init(Cipher.ENCRYPT_MODE, pubkey);
		byte[] cryptogram = verify_cipher.doFinal(nonce);
		verify_cipher.init(Cipher.DECRYPT_MODE, privkey);
		byte[] result = verify_cipher.doFinal(cryptogram);
		if (!Arrays.equals(nonce, result))
			return false;
		
		sr.nextBytes(nonce);
		verify_cipher.init(Cipher.ENCRYPT_MODE, privkey);
		cryptogram = verify_cipher.doFinal(nonce);
		verify_cipher.init(Cipher.DECRYPT_MODE, pubkey);
		result = verify_cipher.doFinal(cryptogram);
		if (!Arrays.equals(nonce, result))
			return false;

		return true;
	}
	
	
	/**
	 * Converts the input keypair to the CRT equivalent to be able to properly export it to PKCS#1 private key ASN.1 structure, required for importing by non-Java software.
	 * 
	 * @param key {@link RSAPrivateKey} to be converted to the {@link RSAPrivateCrtKey} equivalent
	 * @param pubkey Public key part of the input key
	 * @return {@link RSAPrivateCrtKey} equivalent of the input key or an exception if conversion fails.
	 * @throws UnrecoverableKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static RSAPrivateCrtKey convertToCrt(RSAPrivateKey key, RSAPublicKey pubkey) throws UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		RSAPrivateCrtKey crtkey = calculateCrtComponents(key.getModulus(), pubkey.getPublicExponent(), key.getPrivateExponent());
		if (verifyKeypairIntegrity(crtkey, pubkey))
			return crtkey;
		else
			throw new UnrecoverableKeyException("Derived key integrity check failed!");
	}
}
