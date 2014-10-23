package cn.encry2;

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
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import cn.encry.Coder;
      
    /** 
     * DSA安全编码组件 
     *  
     * @version 1.0 
     * @since 1.0 
     */  
    public abstract class DSACoder extends Coder {  
      
        public static final String ALGORITHM = "DSA";  
        
        public static final String test_File = "e:\\my_keystore\\java_key";
        
      
        /** 
         * 默认密钥字节数 
         *  
         * <pre> 
         * DSA  
         * Default Keysize 1024   
         * Keysize must be a multiple of 64, ranging from 512 to 1024 (inclusive). 
         * </pre> 
         */  
        public static final int KEY_SIZE = 1024;  
      
        /** 
         * 默认种子 
         */  
        public static final String DEFAULT_SEED = "0f22507a10bbddd07d8a3082122966e3";  
      
        private static final String PUBLIC_KEY = "DSAPublicKey";  
        private static final String PRIVATE_KEY = "DSAPrivateKey";  
      
        /** 
         * 用私钥对信息生成数字签名 
         *  
         * @param data 
         *            加密数据 
         * @param privateKey 
         *            私钥 
         *  
         * @return 
         * @throws Exception 
         */  
        public static String sign(byte[] data, String privateKey) throws Exception {  
            // 解密由base64编码的私钥  
            byte[] keyBytes = decryptBASE64(privateKey);  
      
            // 构造PKCS8EncodedKeySpec对象  
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  
      
            // KEY_ALGORITHM 指定的加密算法  
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);  
      
            // 取私钥匙对象  
            PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);  
      
            // 用私钥对信息生成数字签名  
            Signature signature = Signature.getInstance(keyFactory.getAlgorithm());  
            signature.initSign(priKey);  
            signature.update(data);  
      
            return encryptBASE64(signature.sign());  
        }  
      
        /** 
         * 校验数字签名 
         *  
         * @param data 
         *            加密数据 
         * @param publicKey 
         *            公钥 
         * @param sign 
         *            数字签名 
         *  
         * @return 校验成功返回true 失败返回false 
         * @throws Exception 
         *  
         */  
        public static boolean verify(byte[] data, String publicKey, String sign)  
                throws Exception {  
      
            // 解密由base64编码的公钥  
            byte[] keyBytes = decryptBASE64(publicKey);  
      
            // 构造X509EncodedKeySpec对象  
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);  
      
            // ALGORITHM 指定的加密算法  
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);  
      
            // 取公钥匙对象  
            PublicKey pubKey = keyFactory.generatePublic(keySpec);  
      
            Signature signature = Signature.getInstance(keyFactory.getAlgorithm());  
            signature.initVerify(pubKey);  
            signature.update(data);  
      
            // 验证签名是否正常  
            return signature.verify(decryptBASE64(sign));  
        }  
      
        /** 
         * 生成密钥 
         *  
         * @param seed 
         *            种子 
         * @return 密钥对象 
         * @throws Exception 
         */  
        public static Map<String, Object> initKey(String seed) throws Exception {  
            KeyPairGenerator keygen = KeyPairGenerator.getInstance(ALGORITHM);  
            // 初始化随机产生器  
            SecureRandom secureRandom = new SecureRandom();  
            secureRandom.setSeed(seed.getBytes());  
            keygen.initialize(KEY_SIZE, secureRandom);  
      
            KeyPair keys = keygen.genKeyPair();  
      
            DSAPublicKey publicKey = (DSAPublicKey) keys.getPublic();  
            DSAPrivateKey privateKey = (DSAPrivateKey) keys.getPrivate();  
      
            Map<String, Object> map = new HashMap<String, Object>(2);  
            map.put(PUBLIC_KEY, publicKey);  
            map.put(PRIVATE_KEY, privateKey);  
      
            return map;  
        }  
        
        public static Map<String, Object> initkey() throws Exception{
    		File f = new File(test_File);
    		ObjectInputStream oi = new ObjectInputStream(new FileInputStream(new File(f, "privkey.der")));
    		PrivateKey privateKey= (PrivateKey) oi.readObject();
    		oi.close();    		
    		oi = new ObjectInputStream(new FileInputStream(new File(f, "pubkey.der")));
    		
    		PublicKey publicKey= (PublicKey) oi.readObject();
    		oi.close();
    		
		   Map<String, Object> map = new HashMap<String, Object>(2);  
           map.put(PUBLIC_KEY, publicKey);  
           map.put(PRIVATE_KEY, privateKey); 
           return map;
    	}
        
        
        
      
        /** 
         * 默认生成密钥 
         *  
         * @return 密钥对象 
         * @throws Exception 
         */  
        public static Map<String, Object> initKey() throws Exception {  
            return initKey(DEFAULT_SEED);  
        }  
      
        /** 
         * 取得私钥 
         *  
         * @param keyMap 
         * @return 
         * @throws Exception 
         */  
        public static String getPrivateKey(Map<String, Object> keyMap)  
                throws Exception {  
            Key key = (Key) keyMap.get(PRIVATE_KEY);  
      
            return encryptBASE64(key.getEncoded());  
        }  
      
        /** 
         * 取得公钥 
         *  
         * @param keyMap 
         * @return 
         * @throws Exception 
         */  
        public static String getPublicKey(Map<String, Object> keyMap)  
                throws Exception {  
            Key key = (Key) keyMap.get(PUBLIC_KEY);  
      
            return encryptBASE64(key.getEncoded());  
        }  
        

    	public static void keyGenerator(String algorithm,int size,String seed) throws NoSuchAlgorithmException, IOException, FileNotFoundException {
    		KeyPairGenerator keyPaireGenerator = KeyPairGenerator.getInstance(algorithm);
    		SecureRandom random = new SecureRandom();
    		random.setSeed(seed.getBytes());
    		keyPaireGenerator.initialize(size, random);

    		KeyPair keyPair = keyPaireGenerator.generateKeyPair();

    		PublicKey publicKey = keyPair.getPublic();
    		//System.out.println("pubKey:"+Base64Encoding.encryptBASE64(publicKey.getEncoded()));
    		PrivateKey privateKey = keyPair.getPrivate();
    		//System.out.println("privKey:"+Base64Encoding.encryptBASE64(privateKey.getEncoded()));
    		File f = new File(test_File);
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
   	 * 公钥解密
   	 * @param data
   	 * @param publicKeyBytes
   	 * @return
   	 * @throws Exception
   	 */
   	public static byte[] decryptByPublicKey(byte[] data, String publicKeys)
   			throws Exception {
   		/*// 解密由base64编码的公钥  
         byte[] keyBytes = decryptBASE64(publicKeys);  
   		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
   		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
   		Key publicKey = keyFactory.generatePublic(x509KeySpec);

   		Cipher cipher = Cipher.getInstance(ALGORITHM);
   		cipher.init(Cipher.DECRYPT_MODE, publicKey);

   		return cipher.doFinal(data);*/
   		
   		
   	  /*   // 解密由base64编码的公钥  
         byte[] keyBytes = decryptBASE64(publicKeys);  
   
         // 构造X509EncodedKeySpec对象  
         X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);  
   
         // ALGORITHM 指定的加密算法  
         KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);  
   
         // 取公钥匙对象  
         PublicKey pubKey = keyFactory.generatePublic(keySpec);  
   
         Signature signature = Signature.getInstance(keyFactory.getAlgorithm());  
         signature.initVerify(pubKey);  
         signature.update(data);  
         return signature.sign();*/
   		return null;
   	}
    	
    }  