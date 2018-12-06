package it.xn__rb_fka.blogchain.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Diese Klasse ist für die Ver- und Entschlüsselung mit dem AES-Algorithmus zuständig.
 * 
 * @author Kevin Röbert
 */
public class AES {
	private String password;
	
	public AES(String _password)
	{
		password = _password;
	}
	
	/**
	 * Verschlüsselt einen String und gibt ihn Base64 codiert zurück.
	 * @param message Klartext
	 * @return Ciphertext
	 */
	public String encrypt(String message)
	{
		SecretKeySpec key = generateKey();
		IvParameterSpec iv = generateIv();
		byte[] IvAndEnc = null;
		
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			
			byte[] enc = cipher.doFinal(message.getBytes("UTF-8"));
			IvAndEnc = new byte[16+enc.length];
			
			System.arraycopy(iv.getIV(), 0, IvAndEnc, 0, 16);
			System.arraycopy(enc, 0, IvAndEnc, 16, enc.length);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}	
		
		return Base64.getEncoder().encodeToString(IvAndEnc);
	}
	
	/**
	 * Entschlüsselt einen Base64 kodierten String.
	 * @param enc Ciphertext
	 * @return Klartext
	 */
	public String decrypt(String enc)
	{
	    byte[] cipherData = null;		
	        
		try {
			SecretKeySpec key = generateKey();
			byte[] decoded = Base64.getDecoder().decode(enc.getBytes("UTF-8"));
			IvParameterSpec iv = extractIVFromMessage(decoded);
			byte[] text = new byte[decoded.length-16];
			System.arraycopy(decoded, 16, text, 0, decoded.length-16);
		    
		    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
		    cipherData = cipher.doFinal(text);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	      
		return new String(cipherData);
	}
	
	/**
	 * Generiert einen Initialisierungsvektor für den AES CBC Mode.
	 * 
	 * @return Initialisierungsvektor
	 */
	private IvParameterSpec generateIv()
	{
		byte[] iv = new byte[16];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		
		return new IvParameterSpec(iv);
	}
	
	/**
	 * Extrahiert den Initialisierungsvektor aus dem Ciphertext.
	 * 
	 * @param ciphertext Ciphertext
	 * @return Initialisierungsvektor
	 */
	private IvParameterSpec extractIVFromMessage(byte[] ciphertext)
	{
		byte[] iv = new byte[16];
		System.arraycopy(ciphertext, 0, iv, 0, iv.length);
		
		return new IvParameterSpec(iv);	
	}
	
	/**
	 * Erstellt den SecretKey für die AES Verschlüsselung.
	 */
	private SecretKeySpec generateKey()
	{
		try {
			byte[] aesKey = password.getBytes("UTF-8");
			//Hash vom Array erzeugen
			MessageDigest sha = MessageDigest.getInstance("SHA-256");
			aesKey = sha.digest(aesKey);

			/*
			 * HASH auf auf richtige Länge für AES-128 kürzen, da
			 * JCE Jurisdiction Policy eine Keylänge größer als 128bit
			 * verbietet ohne manuelle Freischaltung, da es in einigen
			 * Ländern illegal ist, starke Kryptographie einzusetzen.
			 */
			aesKey = Arrays.copyOf(aesKey, 16);
			return new SecretKeySpec(aesKey, "AES");
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		return null;
	}
}
