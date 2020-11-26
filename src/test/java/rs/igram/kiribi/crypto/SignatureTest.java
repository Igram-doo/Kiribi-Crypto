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

import java.io.IOException;
import java.security.KeyPair;
import java.security.SecureRandom;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SignatureTest {
	static final SecureRandom random = new SecureRandom();
	
	static void random(byte[] bytes) {
		random.nextBytes(bytes);
	}

	@Test
	public void testVerify() throws IOException {
		byte[] b1 = new byte[1000];
		random(b1);
		byte[] b2 = new byte[1000];
		random(b2);
		
		Key k1 = Key.generate();
		Key k2 = Key.generate();
		Signature s1 = k1.sign(b1);
		Signature s2 = k2.sign(b2);
   	   
		assertTrue(s1.verify(b1, k1.pk()));
		assertFalse(s1.verify(b1, k2.pk()));
				
		// new
		KeyPair pair1 = Key.generateKeyPair();
		Key.Public publicKey1 = (Key.Public)pair1.getPublic();
		Key.Private privateKey1 = (Key.Private)pair1.getPrivate();
		
		KeyPair pair2 = Key.generateKeyPair();
		Key.Public publicKey2 = (Key.Public)pair2.getPublic();
		Key.Private privateKey2 = (Key.Private)pair2.getPrivate();
		
		s1 = privateKey1.sign(b1);
		s2 = privateKey2.sign(b2);
		assertTrue(s1.verify(b1, publicKey1));
		assertFalse(s1.verify(b1, publicKey2));

	}
}