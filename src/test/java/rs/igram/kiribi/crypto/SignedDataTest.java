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
import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import rs.igram.kiribi.io.*;

public class SignedDataTest {
	static final SecureRandom random = new SecureRandom();
	
	static void random(byte[] bytes) {
		random.nextBytes(bytes);
	}

	public static int random(int bound) {
		return random.nextInt(bound);
	}

	public static long random() {
		return random.nextLong();
	}

	@Test
	public void testVerify() throws IOException {
		var t = new TestEncodable();	
		var pair = KeyPairGenerator.generateKeyPair();
		var publicKey = (EC25519PublicKey)pair.getPublic();
		var privateKey = (EC25519PrivateKey)pair.getPrivate();
		var s = SignedData.signData(t.encode(), privateKey);
		assertTrue(s.verify(publicKey));
		
   }
    
   private static class TestEncodable implements Encodable {
   	   private long l;
   	   private byte[] b;
   	   
   	   TestEncodable() {
   	   	   l = random();
   	   	   int L = 10 + random(10);
   	   	   b = new byte[L];
   	   	   random(b);
   	   }
   	   
   	   TestEncodable(VarInput in) throws IOException {
   	   	   l = in.readLong();
   	   	   b = in.readBytes();
   	   }
   	   
   	   @Override
   	   public void write(VarOutput out) throws IOException {
   	   	   out.writeLong(l);
   	   	   out.writeBytes(b);
   	   }
   	   
   	   @Override
   	   public int hashCode() {return (int)l;}
   	   
   	   @Override
   	   public boolean equals(Object o) {
   	   	   if(o == null || !(o instanceof TestEncodable)) return false;
   	   	   var t = (TestEncodable)o;
   	   	   return l == t.l && Arrays.equals(b, t.b);
   	   }
   }
}