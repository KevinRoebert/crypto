package it.xn__rb_fka.blogchain.crypto;

import static org.junit.Assert.*;

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
	public void doubleHashTest()
	{
		String input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
		String expectedHash = "B7D0FA4FB58CCA05926114B3FFFEE2E8D0AB6B69049F2635BD5F616E8AF09C07";
		
		assertEquals(expectedHash, Hashing.doubleHash(input));
		assertFalse(Hashing.doubleHash(input).equals("FooBar"));
	}
}
