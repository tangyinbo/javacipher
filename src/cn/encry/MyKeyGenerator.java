package cn.encry;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class MyKeyGenerator {
	private static final String ALGORITHM="DSA";
	private static final String CIPHER_ALGORITHM="DES/CBC/PKCS5Padding";
	private static final int KEY_SIZE=1024;
	private static  byte[] PRIV_KEY;
	private static  byte[] PUBLIC_KEY;
	private static Key publicKey;
	private static Key privateKey;
	private static String SEED="0f22507a10bbddd07d8a3082122966e3";
	
	private static final String CHARSET ="utf-8";
	
	static{
		try {
			initkey();
			System.out.println("公钥获取成功,私钥获取成功");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) throws Exception {
		//keyGenerator(ALGORITHM,KEY_SIZE,SEED);
		String s = "hehe";
		System.out.println(sign(s));
	}
	public static void initkey() throws Exception{
		File f = new File("H:\\my_keystore\\java_key");
		ObjectInputStream oi = new ObjectInputStream(new FileInputStream(new File(f, "privkey.der")));
		PrivateKey privateKey= (PrivateKey) oi.readObject();
		PRIV_KEY = privateKey.getEncoded();
		oi.close();
		
		oi = new ObjectInputStream(new FileInputStream(new File(f, "pubkey.der")));
		
		PublicKey publicKey= (PublicKey) oi.readObject();
		PUBLIC_KEY = publicKey.getEncoded();
		oi.close();
	}
	public static void initkey2() throws Exception{
		File f = new File("H:\\my_keystore\\java_key");
		ObjectInputStream oi = new ObjectInputStream(new FileInputStream(new File(f, "privkey.der")));
		privateKey= (PrivateKey) oi.readObject();
		System.out.println(privateKey.getEncoded().length);
		oi.close();
		
		oi = new ObjectInputStream(new FileInputStream(new File(f, "pubkey.der")));
		
		publicKey= (PublicKey) oi.readObject();
		System.out.println(publicKey.getEncoded().length);
		oi.close();
	}
	private static String bytes2hex(byte[] bArr) {
		// 一个字节的数转成16进制字符串
		String hs = "";
		String stmp = "";
		for (int i = 0; i < bArr.length; i++) {
			// 整数转成十六进制表示
			stmp = (Integer.toHexString(bArr[i] & 0XFF));
			if (stmp.length() == 1)
				hs = hs + "0" + stmp;
			else
				hs = hs + stmp;
		}
		return hs.toUpperCase(); // 转成大写
	}

	private static byte[] hex2Bytes(String hex) {
		int len = (hex.length() / 2);
		byte[] result = new byte[len];
		char[] achar = hex.toCharArray();
		for (int i = 0; i < len; i++) {
			int pos = i * 2;
			result[i] = (byte) (toByte(achar[pos]) << 4 | toByte(achar[pos + 1]));
		}
		return result;
	}

	private static byte toByte(char c) {
		byte b = (byte) "0123456789ABCDEF".indexOf(c);
		return b;
	}
	
	private static void keyGenerator(String algorithm,int size,String seed) throws NoSuchAlgorithmException, IOException, FileNotFoundException {
		KeyPairGenerator keyPaireGenerator = KeyPairGenerator.getInstance(algorithm);
		SecureRandom random = new SecureRandom();
		random.setSeed(seed.getBytes());
		keyPaireGenerator.initialize(size, random);

		KeyPair keyPair = keyPaireGenerator.generateKeyPair();

		PublicKey publicKey = keyPair.getPublic();
		//System.out.println("pubKey:"+Base64Encoding.encryptBASE64(publicKey.getEncoded()));
		PrivateKey privateKey = keyPair.getPrivate();
		//System.out.println("privKey:"+Base64Encoding.encryptBASE64(privateKey.getEncoded()));
		File f = new File("H:\\my_keystore\\java_key");
		if(!f.exists()){
			f.mkdirs();
		}
		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File(f, "pubkey.der")));
		oos.writeObject(publicKey);

		oos.flush();
		oos.close();

		oos = new ObjectOutputStream(new FileOutputStream(new File(f, "privkey.der")));
		oos.writeObject(privateKey);

		oos.flush();
		oos.close();
	}
	
	
	/**
	 * 测试key
	 * @throws Exception
	 */
	public static void rightKey() throws Exception{
		File f = new File("H:\\my_keystore\\java_key");
		ObjectInputStream oi = new ObjectInputStream(new FileInputStream(new File(f, "privkey.der")));
		PrivateKey privateKey= (PrivateKey) oi.readObject();
		System.out.println("privKey:"+Base64Encoding.encryptBASE64(privateKey.getEncoded()));
		oi.close();
		
		oi = new ObjectInputStream(new FileInputStream(new File(f, "pubkey.der")));
		
		PublicKey publicKey= (PublicKey) oi.readObject();
		System.out.println("publicKey:"+Base64Encoding.encryptBASE64(publicKey.getEncoded()));
		oi.close();
		
	}
	
	/**
	 * 公钥加密
	 * @param data
	 * @param publicKeyBytes
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, byte[] publicKeyBytes)
			throws Exception {

		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		Key publicKey = keyFactory.generatePublic(x509KeySpec);

		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		return cipher.doFinal(data);
	}
	
	/**
	 * 公钥加密
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String encryptByPublicKey(String data) throws Exception {
		return bytes2hex(encryptByPublicKey(data.getBytes(CHARSET),
				PUBLIC_KEY));
	}
	
	
	/**
	 * 私钥钥签名
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String sign(String data) throws Exception {
		return encryptByPrivateKey(MD5Encode(data));
	}
	/**
	 * 私钥加密
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String encryptByPrivateKey(String data) throws Exception {
		return bytes2hex(encryptByPrivateKey(data.getBytes(CHARSET),
				PRIV_KEY));
	}

	/**
	 * 公钥签名
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String signByPublicKey(String data) throws Exception {
		return encryptByPublicKey(MD5Encode(data));
	}

	/**
	 * MD5
	 * @param data
	 * @return
	 * @throws Exception
	 */
	private static byte[] MD5Encode(byte[] data) throws Exception {
		MessageDigest md = MessageDigest.getInstance("MD5");
		return md.digest(data);

	}

	/**
	 * MD5
	 * @param data
	 * @return
	 * @throws Exception
	 */
	private static String MD5Encode(String data) throws Exception {
		return bytes2hex(MD5Encode(data.getBytes(CHARSET)));

	}

	/**
	 * 私钥加密
	 * @param data
	 * @param privatekeyBytes
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data, byte[] privatekeyBytes)
			throws Exception {

		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(
				privatekeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);

		return cipher.doFinal(data);
	}
	
	

	/**
	 * 公钥解密
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data) throws Exception {
		return decryptByPublicKey(data, PUBLIC_KEY);
	}

	/**
	 * 公钥解密
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String decryptByPublicKey(String data) throws Exception {
		return new String(decryptByPublicKey(hex2Bytes(data), PUBLIC_KEY),
				CHARSET);
	}
	
	/**
	 * 公钥解密
	 * @param data
	 * @param publicKeyBytes
	 * @return
	 * @throws Exception
	 */
	public static String decryptByPublicKey(String data, byte[] publicKeyBytes) throws Exception {
		return new String(decryptByPublicKey(hex2Bytes(data), publicKeyBytes),
				CHARSET);
	}

	/**
	 * 公钥解密
	 * @param data
	 * @param publicKeyBytes
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data, byte[] publicKeyBytes)
			throws Exception {

		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		Key publicKey = keyFactory.generatePublic(x509KeySpec);

		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, publicKey);

		return cipher.doFinal(data);
	}
	
	
	/**
	 * 私钥解密
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data) throws Exception {
		return decryptByPrivateKey(data, PRIV_KEY);
	}

	/**
	 * 私钥解密
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String decryptByPrivateKey(String data) throws Exception {
		return new String(
				(decryptByPrivateKey(hex2Bytes(data), PRIV_KEY)),
				CHARSET);
	}
	
	/**
	 * 私钥解密
	 * @param data
	 * @param privateKeyBytes
	 * @return
	 * @throws Exception
	 */
	public static String decryptByPrivateKey(String data,byte[] privateKeyBytes) throws Exception {
		return new String(
				(decryptByPrivateKey(hex2Bytes(data), privateKeyBytes)),
				CHARSET);
	}

	/**
	 * 私钥解密
	 * @param data
	 * @param privateKeyBytes
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data, byte[] privateKeyBytes)
			throws Exception {

		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(
				privateKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		return cipher.doFinal(data);
	}
	
	/**
    * 加密方法
    * @param source 源数据
    * @return
    * @throws Exception
    */
   public static String encrypt(String source) throws Exception {
       
       /** 得到Cipher对象来实现对源数据的RSA加密 */
       Cipher cipher = Cipher.getInstance(ALGORITHM);
       cipher.init(Cipher.ENCRYPT_MODE, publicKey);
       byte[] b = source.getBytes();
       /** 执行加密操作 */
       byte[] b1 = cipher.doFinal(b);
       BASE64Encoder encoder = new BASE64Encoder();
       return encoder.encode(b1);
   }

   /**
    * 解密算法
    * @param cryptograph    密文
    * @return
    * @throws Exception
    */
   public static String decrypt(String cryptograph) throws Exception {
       
       /** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */
       Cipher cipher = Cipher.getInstance(ALGORITHM);
       cipher.init(Cipher.DECRYPT_MODE, privateKey);
       BASE64Decoder decoder = new BASE64Decoder();
       byte[] b1 = decoder.decodeBuffer(cryptograph);
       
       /** 执行解密操作 */
       byte[] b = cipher.doFinal(b1);
       return new String(b);
   }
   
   
}
