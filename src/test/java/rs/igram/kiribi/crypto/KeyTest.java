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
import java.security.Security;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.*;
import javax.crypto.spec.*;

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
		var pair = KeyPairGenerator.generateKeyPair();
		var publicKey = (EC25519PublicKey)pair.getPublic();
		var privateKey = (EC25519PrivateKey)pair.getPrivate();
		
		var baos = new ByteArrayOutputStream();
		var oos = new ObjectOutputStream(baos);
		oos.writeObject(publicKey);
		oos.writeObject(privateKey);
		oos.flush();
		oos.close();
 
		var data = baos.toByteArray();
		
		var bais  = new ByteArrayInputStream(data);
		var ois  = new ObjectInputStream(bais);
		var test1 = (EC25519PublicKey) ois.readObject();
		var test2 = (EC25519PrivateKey) ois.readObject();
		ois.close();
		assertEquals(publicKey, test1);
		assertEquals(privateKey, test2);
	}
}