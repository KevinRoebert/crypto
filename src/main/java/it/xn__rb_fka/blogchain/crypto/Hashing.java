package it.xn__rb_fka.blogchain.crypto;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hashing {

    /**
     * Berechnet einen SHA256 Hashwert von einem gegebenen String.
     * 
     * @param message String von dem der Hashwert berechnert werden soll
     * @return SHA256 Hash von message
     */
    public static String sha256(String message) {
        return sha256(message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Berechnet einen SHA256 Hashwert von einem gegebenen Byte-Array.
     * 
     * @param message Byte-Array von dem der Hashwert berechnet werden soll
     * @return SHA256 Hash von message
     */
    public static String sha256(byte[] message) {
        StringBuffer sb = new StringBuffer();

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(message);
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
     * Berechnet einen SHA256 Hashwert von einem gegebenen DigestInputStream.
     * 
     * @param digestStream DigestInputStream von dem der Hashwert berechnet werden
     *                     soll
     * @return SHA256 Hash von digestStream
     */
    public static String sha256(DigestInputStream digestStream) {
        StringBuffer sb = new StringBuffer();

        MessageDigest digest = digestStream.getMessageDigest();
        byte byteData[] = digest.digest();

        for (int i = 0; i < byteData.length; i++) {
            sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString().toUpperCase();
    }

    /**
     * Berechnet einen SHA256 Hashwert von einem gegebenen DigestInputStream.
     * 
     * @param digestStream DigestOutputStream von dem der Hashwert berechnet werden
     *                     soll
     * @return SHA256 Hash von digestStream
     */
    public static String sha256(DigestOutputStream digestStream) {
        StringBuffer sb = new StringBuffer();

        MessageDigest digest = digestStream.getMessageDigest();
        byte byteData[] = digest.digest();

        for (int i = 0; i < byteData.length; i++) {
            sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString().toUpperCase();
    }

    /**
     * Berechnet einen SHA256 Hashwert von einer gegebenen Datei.
     * 
     * @param file Datei von der der Hashwert berechnet werden soll
     * @return SHA245 Hash von der Datei
     */
    public static String sha256(File file) {
        try {
            return sha256(new DigestInputStream(new BufferedInputStream(new FileInputStream(file)),
                    MessageDigest.getInstance("SHA-256")));
        } catch (FileNotFoundException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * Erstellt einen double SHA256 Hashwert von einem gegebenen String.
     * 
     * @param message String von dem der Hashwert berechnert werden soll
     * @return double SHA256 Hash von message
     */
    public static String doubleHash(String message) {
        return doubleHash(message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Erstellt einen double SHA256 Hashwert von einem gegebenen Byte-Array.
     * 
     * @param message Byte-Array von dem der Hashwert berechnert werden soll
     * @return double SHA256 Hash von message
     */
    public static String doubleHash(byte[] message) {
        return sha256(sha256(message));
    }

    /**
     * Erstellt einen MD5 Hashwert von einem gegebenen String.
     * 
     * @param message String von dem der Hashwert berechnet werden soll
     * @return MD5 Hash von message
     */
    public static String md5(String message) {
        return md5(message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Erstellt einen MD5 Hashwert von einem gegebenen Byte-Array.
     * 
     * @param message Byte-Array von dem der Hashwert berechnet werden soll
     * @return MD5 Hash von message
     */
    public static String md5(byte[] message) {
        StringBuffer sb = new StringBuffer();

        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte byteData[] = md.digest(message);

            for (byte b : byteData) {
                sb.append(String.format("%02x", b));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return sb.toString().toUpperCase();
    }
}
