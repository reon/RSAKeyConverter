package opensc;

import java.io.Console;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSAKeyConverterTool {

	/**
	 * @param args
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws UnrecoverableKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeySpecException 
	 * @throws InvalidKeyException 
	 */
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		if (args.length < 2) {
			System.err.println("Usage:\nopensc.RSAKeyConverterTool input.p12 output.p12 [password]");
			System.exit(1);
		}
		
		Console cons = System.console();
		char [] pass;
		String oldkeystore = args[0];
		String newkystore = args[1];
		if (args.length != 3)
			pass = cons.readPassword("%s: ", "Password for " + oldkeystore);
		else
			pass = args[2].toCharArray();

		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream(oldkeystore), pass);
		
		ArrayList<String> aliases = Collections.list(ks.aliases());
		String alias = null;
		if (aliases.size() == 0) {
			System.err.println("No aliases found in " + oldkeystore);
			System.exit(1);
		}
		if (aliases.size() == 1) {
			alias = aliases.get(0);
			System.err.println("Using alias \"" + alias + "\"");
		} else {
			alias = new String(cons.readLine("%s: ", "Alias"));
		}

		RSAPrivateKey key = (RSAPrivateKey) ks.getKey(alias, pass);
		X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
		
		RSAPrivateCrtKey crt = RSAKeyConverter.convertToCrt(key, (RSAPublicKey) cert.getPublicKey());
		
		KeyStore newks =  KeyStore.getInstance("PKCS12");
		newks.load(null, null);
		newks.setKeyEntry(alias, (Key) crt, pass, new Certificate[] {cert});
		FileOutputStream fos = new FileOutputStream(newkystore);
		newks.store(fos, pass);
		System.err.println("Wrote new keystore with the same password to " + newkystore);
	}

}
