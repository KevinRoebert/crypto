package it.xn__rb_fka.blogchain.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class Hashing {

	/**
	 * Berechnet einen SHA256 Hashwert von einem gegebenen String.
	 * 
	 * @param message
	 *            String von dem der Hashwert berechnert werden soll
	 * @return SHA256 Hash von message
	 */
	public static String sha256(String message) {
		StringBuffer sb = new StringBuffer();

		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(message.getBytes());
			byte byteData[] = md.digest();

			for (int i = 0; i < byteData.length; i++) {
				sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return sb.toString().toUpperCase();
	}

	/**
	 * Erstellt einen double SHA256 Hashwert von einem gegebenen String.
	 * 
	 * @param message
	 *            String von dem der Hashwert berechnert werden soll
	 * @return double SHA256 Hash von message
	 */
	public static String doubleHash(String message) {
		return sha256(sha256(message));
	}

	/**
	 * Erstellt einen MD5 Hashwert von einem gegebenen String.
	 * 
	 * @param message
	 *            String von dem der Hashwert berechnet werden soll
	 * @return MD5 Hash von message
	 */
	public static String md5(String message) {
		StringBuffer sb = new StringBuffer();

		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte byteData[] = md.digest(message.getBytes(StandardCharsets.UTF_8));

			for (byte b : byteData) {
				sb.append(String.format("%02x", b));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return sb.toString().toUpperCase();
	}
}
