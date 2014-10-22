package cn.encry;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Encoding {
	public static void main(String[] args) throws Exception {
		String info ="你是谁啊fsfsffsfsfs";
		System.out.println(md5Encrypt(info.getBytes()));
	}

	/**
	 * 通常我们不直接使用上述MD5加密。
	 * 通常将MD5产生的字节数组交给BASE64再加密一把，
	 * 得到相应的字符串
	 * @param input
	 * @return
	 * @throws Exception
	 */
	public static String  md5Encrypt(byte[] input) throws Exception{
		MessageDigest digest = MessageDigest.getInstance("MD5");
		digest.update(input);
		byte[] bts = digest.digest();
		System.out.println(bytes2hex(bts));
		return Base64Encoding.encryptBASE64(bts);
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
}
