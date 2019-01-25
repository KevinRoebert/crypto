package it.xn__rb_fka.blogchain.crypto;

import static org.junit.Assert.*;
import java.io.IOException;
import org.junit.Test;

import it.xn__rb_fka.blogchain.exceptions.ECDSAException;

public class ECDSATest {

	@Test
	public void saveAndLoadTest() throws ECDSAException, IOException
	{
		AES aes1 = new AES("test1");

		ECDSA r = new ECDSA(aes1);
		ECDSA r2 = null;
			
		r.savePublicKey("test1");
		r.savePrivateKey("test1");
		r2 = new ECDSA("test1", aes1);
			
		r2.savePrivateKey("test2");
		r2.savePublicKey("test2");
			
		assertEquals(r, r2);
		assertFalse(r.equals("Test"));
	}
	
	@Test
	public void signAndVerifyTest() throws ECDSAException
	{
		AES aes1 = new AES("password");

		ECDSA r = new ECDSA(aes1);
		String message = "Test";
		String signature = "";
			
		signature = r.sign(message);
		assertTrue(ECDSA.verifySign(message, signature, new ECDSA().pubKey2Base64(r.getPublicKey())));	
	}

}
