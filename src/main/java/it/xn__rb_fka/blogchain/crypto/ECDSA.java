package it.xn__rb_fka.blogchain.crypto;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import it.xn__rb_fka.blogchain.exceptions.ECDSAException;



public class ECDSA {
	private final PrivateKey 	_privateKey;
	private final PublicKey 	_publicKey;
	private final AES			_aes;
	
	
	public ECDSA() {
		_privateKey = null;
		_publicKey = null;
		_aes = null;
	}
	
	/**
	 * Generiert ein default ECDSA-Objekt mit einem neuen Schlüsselpaar.
	 * 
	 * @param aes Passwort, mit dem der private Schlüssel gesichert ist als AES-Instanz
	 * @throws ECDSAException 
	 * @throws IOException 
	 */
	public ECDSA(AES aes) throws ECDSAException
	{
		_aes = aes;

		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("B-571");
			KeyPairGenerator g;
			g = KeyPairGenerator.getInstance("ECDSA", "BC");
			g.initialize(ecSpec, new SecureRandom());
			KeyPair keypair = g.generateKeyPair(); 
			_privateKey = keypair.getPrivate();
			_publicKey = keypair.getPublic();
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			throw new ECDSAException();
		}

	}
	
	/**
	 * Generiert ein ECDSA-Objekt anhand der im Speichpfad angegebenen Schlüsseldateien.
	 * 
	 * @param path Speicherpfad des privaten und öffentlichen Schlüssels
	 * @param aes Passwort, mit dem der private Schlüssel gesichert ist als AES-Instanz
	 * @throws ECDSAException 
	 * @throws IOException 
	 */
	public ECDSA(String path, AES aes) throws ECDSAException, IOException
	{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		_aes = aes;
		_privateKey = loadPrivateKey(path);
		_publicKey = loadPublicKey(path);	
	}
	
	/**
	 * Gibt den publicKey zurück.
	 * 
	 * @return PublicKey Objekt
	 */
	public PublicKey getPublicKey()
	{
		return _publicKey;
	}
	
	/**
	 * Gibt den privateKey zurück.
	 * 
	 * @return PrivateKey Objekt
	 */
	public PrivateKey getPrivateKey()
	{
		return _privateKey;
	}
	
	/**
	 * Signiert eine Nachricht mit dem privaten Schlüssel dieses ECDSA-Objekts.
	 * 
	 * @param message Nachricht die signiert werden soll
	 * @return Signatur der Nachricht
	 * @throws ECDSAException 
	 */
	public String sign(String message) throws ECDSAException
	{
		try {
			byte[] data = message.getBytes("UTF8");
			Signature sign = Signature.getInstance("SHA512withECDSA", "BC");
			sign.initSign(_privateKey);
			sign.update(data);
			
			return Base64.getEncoder().encodeToString(sign.sign());
		} catch (UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
			e.printStackTrace();
			throw new ECDSAException("An unexpected error occurred in the ECDSA sign routine.");
		}
	}
	
	/**
	 * Hilfsmethode die eingeführt wurde damit mit Mockito in den Tests gearbeitet werden kann.
	 * Mach das gleich wie die Static Methode verifySign.
	 * 
	 * @param message
	 * @param sign
	 * @param pubKey
	 * @return
	 * @throws ECDSAException
	 */
	public boolean verifySignature(String message, String sign, String pubKey) throws ECDSAException {
		return ECDSA.verifySign(message, sign, pubKey);
	}
	
	/**
	 * Verifiziert die Signatur einer Nachricht
	 * 
	 * @param sign
	 * @param pubKey
	 * @return
	 * @throws RSAException
	 */
	public static boolean verifySign(String message, String sign, String pubKey) throws ECDSAException
	{
		try {
			Signature s = Signature.getInstance("SHA512withECDSA", "BC");
			s.initVerify(base642PubKey(pubKey));
			s.update(message.getBytes("UTF8"));
			
			return s.verify(Base64.getDecoder().decode(sign));
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | UnsupportedEncodingException | NoSuchProviderException e) {
			e.printStackTrace();
			throw new ECDSAException("An unexpected error occurred in the ECDSA verify sign routine.");
		}

	}
	
	/**
	 * Speichert den privaten Schlüssel unter den angegebenen Pfad.
	 * 
	 * @param savePath Speicherpfad
	 */
	public void savePrivateKey(String savePath)
	{
		Path dir = Paths.get(savePath+ ".pem");
		
		try(BufferedWriter writer = Files.newBufferedWriter(dir))
		{
			writer.write(_aes.encrypt(privKey2Base64(_privateKey)));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Speichert den öffentlichen Schlüssel unter den angegebenen Pfad.
	 * 
	 * @param savePath Speicherpfad
	 */
	public void savePublicKey(String savePath)
	{
		Path dir = Paths.get(savePath+ ".crt");
		
		try(BufferedWriter writer = Files.newBufferedWriter(dir))
		{
			writer.write(pubKey2Base64(_publicKey));
		} catch (IOException e) {
			e.printStackTrace();
		}	
	}
	
	/**
	 * Konvertiert einen Base64 codierten String in ein PublicKey Objekt.
	 * 
	 * @param pubKey Base64 codierter PublicKey
	 * @return PublicKey Objekt
	 * @throws RSAException 
	 */
	public static PublicKey base642PubKey(String pubKey) throws ECDSAException
	{

		try {		
			byte[] key = Base64.getDecoder().decode(pubKey);
			KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(key);
			
			return keyFactory.generatePublic(publicKeySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
			e.printStackTrace();
			throw new ECDSAException("An unexpected error occurred in the ECDSA base64PubKey routine.");
		}

	}
	
	/**
	 * Konvertiert ein PublicKey Objekt in einen Base64 kodierten String.
	 * 
	 * @param pubKey PublicKey der kodiert werdern soll
	 * @return PublicKey als Base64 String
	 */
	public static String pubKey2Base64(PublicKey pubKey)
	{
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pubKey.getEncoded());
		
		return Base64.getEncoder().encodeToString(x509EncodedKeySpec.getEncoded());
	}
	
	/**
	 * Konvertiert einen Base64 codierten String in ein PrivateKey Objekt.
	 * 
	 * @param privKey Base64 codierter PrivateKey
	 * @return PrivateKey Objekt
	 * @throws RSAException 
	 */
	public static PrivateKey base642PrivKey(String privKey) throws ECDSAException
	{
		try {
			byte[] key = Base64.getDecoder().decode(privKey);
			KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);
			
			return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
			throw new ECDSAException("An unexpected error occurred in the ECDSA base642PrivKey routine.");
		}
	}
	
	/**
	 * Konvertiert ein PrivateKey Objekt in einen Base64 kodierten String.
	 * 
	 * @param privKey PrivateKey Objekt das kodiert werden soll
	 * @return PrivateKey als Base64 String
	 */
	public static String privKey2Base64(PrivateKey privKey)
	{
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privKey.getEncoded());
		
		return Base64.getEncoder().encodeToString(pkcs8EncodedKeySpec.getEncoded());
	}
	
	/**
	 * Lädt den privaten Schlüssel unter den angegebenen Pfad.
	 * 
	 * @param savePath Speicherpfad
	 * @return privater Schlüssel
	 * @throws RSAException 
	 * @throws IOException 
	 */
	private PrivateKey loadPrivateKey(String savePath) throws ECDSAException, IOException
	{
		Path path = Paths.get(savePath+".pem");
		
		return base642PrivKey(_aes.decrypt(new String(Files.readAllBytes(path))));
	}
	
	/**
	 * Lädt den öffentlichen Schlüssel unter den angegebenen Pfad.
	 * 
	 * @param savePath Speicherpfad
	 * @return öffentlicher Schlüssel
	 * @throws RSAException 
	 * @throws IOException 
	 */
	private PublicKey loadPublicKey(String savePath) throws ECDSAException, IOException
	{
		Path path = Paths.get(savePath+".crt");
		
		return base642PubKey(new String(Files.readAllBytes(path)));
	}
	
	@Override
	public boolean equals(Object o)
	{
		if(o instanceof ECDSA)
		{
			String priO = privKey2Base64(((ECDSA) o)._privateKey);
			String pubO = pubKey2Base64(((ECDSA) o)._publicKey);
			String priT = privKey2Base64(_privateKey);
			String pubT = pubKey2Base64(_publicKey);
			
			if(priO.equals(priT) && pubO.equals(pubT))
			{
				return true;
			}
		}
		
		return false;
	}
}
