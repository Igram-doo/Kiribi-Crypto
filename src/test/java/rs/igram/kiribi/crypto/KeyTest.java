/* 
 * MIT License
 * 
 * Copyright (c) 2020 Igram, d.o.o.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
 
package rs.igram.kiribi.crypto;

import java.io.*;
import java.io.IOException;
//import java.security.*;
import java.security.KeyPair;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class KeyTest {
	static final SecureRandom random = new SecureRandom();
	
	static void random(byte[] bytes) {
		random.nextBytes(bytes);
	}

	@Test
	public void testSerializable() throws Exception {
		KeyPair pair = KeyPairGenerator.generateKeyPair();
		EC25519PublicKey publicKey = (EC25519PublicKey)pair.getPublic();
		EC25519PrivateKey privateKey = (EC25519PrivateKey)pair.getPrivate();
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(publicKey);
		oos.writeObject(privateKey);
		oos.flush();
		oos.close();
 
		byte[] data = baos.toByteArray();
		
		ByteArrayInputStream bais  = new ByteArrayInputStream(data);
		ObjectInputStream ois  = new ObjectInputStream(bais);
		EC25519PublicKey test1 = (EC25519PublicKey) ois.readObject();
		EC25519PrivateKey test2 = (EC25519PrivateKey) ois.readObject();
		ois.close();
		assertEquals(publicKey, test1);
		assertEquals(privateKey, test2);
	}

	@Test
	public void testKeyStore() throws Exception {
		/*
		Security.setProperty("crypto.policy", "unlimited");
		KeyPair pair = Key.generateKeyPair();
		Key.Public publicKey = (Key.Public)pair.getPublic();
		Key.Private privateKey = (Key.Private)pair.getPrivate();
		
		Key.Cert[] certs = new Key.Cert[] {new Key.Cert(publicKey)};
		
		KeyStore keystore = KeyStore.getInstance("JKS");
		keystore.load(null, "mypass".toCharArray());
		KeyStore.PasswordProtection keyPP = new KeyStore.PasswordProtection("mypass".toCharArray());
		System.out.println("TURD: " + keyPP.getProtectionAlgorithm());
		System.out.println("CRAP: " + certs + " " + privateKey);
		KeyStore.PrivateKeyEntry skey = new KeyStore.PrivateKeyEntry(privateKey, certs);
		
		keystore.setEntry("mypass", skey, keyPP);
		System.out.println("SHIT: ");
		KeyStore.PrivateKeyEntry test = (KeyStore.PrivateKeyEntry)keystore.getEntry("mypass", keyPP);
		System.out.println("FUCK: " + test);
	//	assertEquals(publicKey.address(), test1.address());
	//	assertEquals(privateKey, test2);
	*/
	}

	@Test
	public void testVerifySignature() throws IOException {
		byte[] b = new byte[1000];
		random(b);
		
		KeyPair pair = KeyPairGenerator.generateKeyPair();
		EC25519PublicKey publicKey = (EC25519PublicKey)pair.getPublic();
		EC25519PrivateKey privateKey = (EC25519PrivateKey)pair.getPrivate();
		Signature s = privateKey.sign(b);
		assertTrue(s.verify(b, publicKey));
	}

	@Test
	public void testVerifySignedData() throws IOException {
		byte[] b = new byte[1000];
		random(b);
		
		KeyPair pair = KeyPairGenerator.generateKeyPair();
		EC25519PublicKey publicKey = (EC25519PublicKey)pair.getPublic();
		EC25519PrivateKey privateKey = (EC25519PrivateKey)pair.getPrivate();
		SignedData d = privateKey.signData(b);
		assertTrue(d.verify(publicKey));
		assertEquals(publicKey, d.getPublicKey());
	}
}