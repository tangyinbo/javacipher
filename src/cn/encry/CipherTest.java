package cn.encry;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

public class CipherTest {
	public static void main(String[] args) throws Exception {
		keyGenerator();

	}

	private static void keyGenerator() throws NoSuchAlgorithmException, IOException, FileNotFoundException {
		KeyPairGenerator keyPaireGenerator = KeyPairGenerator.getInstance("DSA");
		SecureRandom random = new SecureRandom();
		random.setSeed("tyb".getBytes());
		keyPaireGenerator.initialize(512, random);

		KeyPair keyPair = keyPaireGenerator.generateKeyPair();

		PublicKey publicKey = keyPair.getPublic();

		PrivateKey privateKey = keyPair.getPrivate();

		File f = new File("H:\\my_keystore\\java_key");
		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File(f, "pubkey.der")));
		oos.writeObject(publicKey);

		oos.flush();
		oos.close();

		oos = new ObjectOutputStream(new FileOutputStream(new File(f, "privkey.der")));
		oos.writeObject(privateKey);

		oos.flush();
		oos.close();
	}
	
	
	public static void privKeySign() throws Exception{
		String info = "我是一段文字";
		File f = new File("H:\\my_keystore\\java_key");
		ObjectInputStream oi = new ObjectInputStream(new FileInputStream(new File(f, "privkey.dat")));
		PrivateKey privateKey= (PrivateKey) oi.readObject();
		
		oi.close();
		
		Signature sign  = Signature.getInstance("DSA");
		
		sign.initSign(privateKey);
		sign.update(info.getBytes());
		byte[] bt = sign.sign();
		
		//System.out.println(Charset.);
		
		
	}
}
