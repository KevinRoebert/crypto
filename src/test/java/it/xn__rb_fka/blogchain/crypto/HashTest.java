package it.xn__rb_fka.blogchain.crypto;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

public class HashTest {
	@Test
	public void sha256Test() 
	{
		String input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
		String expectedHash = "973153F86EC2DA1748E63F0CF85B89835B42F8EE8018C549868A1308A19F6CA3";
		
		assertEquals(expectedHash, Hashing.sha256(input));
		assertFalse(Hashing.sha256(input).equals("FooBar"));
	}
	
	@Test
	public void streamInputTest() throws NoSuchAlgorithmException, IOException
	{
		String input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
		String expectedHash = "973153F86EC2DA1748E63F0CF85B89835B42F8EE8018C549868A1308A19F6CA3";
		InputStream is = new ByteArrayInputStream(input.getBytes());
		DigestInputStream dis = new DigestInputStream(is, MessageDigest.getInstance("SHA-256"));
		dis.read(new byte[input.getBytes().length]);
		
		assertEquals(expectedHash, Hashing.sha256(dis));
		assertFalse(Hashing.sha256(dis).equals("FooBar"));
	}
	
	@Test
	public void streamOutputTest() throws NoSuchAlgorithmException, IOException
	{
		String input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
		String expectedHash = "973153F86EC2DA1748E63F0CF85B89835B42F8EE8018C549868A1308A19F6CA3";
		OutputStream out = new ByteArrayOutputStream();
		DigestOutputStream dis = new DigestOutputStream(out, MessageDigest.getInstance("SHA-256"));
		out.write(input.getBytes(), 0, input.getBytes().length);
		dis.write(input.getBytes(), 0, input.getBytes().length);
		dis.close();
		out.close();
		
		assertEquals(expectedHash, Hashing.sha256(dis));
		assertFalse(Hashing.sha256(dis).equals("FooBar"));
	}
	
	@Test
	public void doubleHashTest()
	{
		String input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
		String expectedHash = "B7D0FA4FB58CCA05926114B3FFFEE2E8D0AB6B69049F2635BD5F616E8AF09C07";
		
		assertEquals(expectedHash, Hashing.doubleHash(input));
		assertFalse(Hashing.doubleHash(input).equals("FooBar"));
	}
	
	@Test
	public void md5Test()
	{
		String input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
		String expectedHash = "818C6E601A24F72750DA0F6C9B8EBE28";
		
		assertEquals(expectedHash, Hashing.md5(input));
		assertFalse(Hashing.md5(input).equals("FooBar"));
	}
}
