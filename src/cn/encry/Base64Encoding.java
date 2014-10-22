package cn.encry;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Base64Encoding {
	public static void main(String[] args) throws IOException {
		String info ="我是中国人";
		String encodeInfo = encryptBASE64(info);
		String decodeInfo = decryptBASE64(encodeInfo);
		System.out.println("encodeInfo: "+encodeInfo);
		System.out.println("decodeInfo: "+decodeInfo);
	}
	
	public static String decryptBASE64(String s) throws IOException{
		byte[] bts =new BASE64Decoder().decodeBuffer(s);
		return new String(bts);
	}
	
	public static String encryptBASE64(String s ) throws UnsupportedEncodingException{
		return new BASE64Encoder().encode(s.getBytes());
	}
	
	public static String encryptBASE64(byte[] data ) throws UnsupportedEncodingException{
		return new BASE64Encoder().encode(data);
	}
}
