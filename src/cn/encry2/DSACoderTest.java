package cn.encry2;

import java.util.Map;
  
/** 
 *  
 * @author 
 * @version 1.0
 * @since 1.0
 */  
public class DSACoderTest {  
  
    public static void test() throws Exception {
        String inputStr = "abc";
        byte[] data = inputStr.getBytes();  
  
        //生成文件
        DSACoder.keyGenerator(DSACoder.ALGORITHM, DSACoder.KEY_SIZE, DSACoder.DEFAULT_SEED);
        // 构建密钥  
        Map<String, Object> keyMap = DSACoder.initkey();  
  
        // 获得密钥  
        String publicKey = DSACoder.getPublicKey(keyMap);  
        String privateKey = DSACoder.getPrivateKey(keyMap);  
  
        System.err.println("公钥:\r" + publicKey);  
        System.err.println("私钥:\r" + privateKey);  
  
        // 产生签名  
        String sign = DSACoder.sign(data, privateKey);  
        System.err.println("签名:\r" + sign); 
        
        
       // byte[] bts = DSACoder.decryptByPublicKey(data,publicKey);
        
        //System.out.println(bts.length);
        // 验证签名  
        boolean status = DSACoder.verify(data, publicKey, sign);  
        System.err.println("状态:\r" + status);
  
    }  
    
    public static void main(String[] args) throws Exception {
		test();
	}
  
}