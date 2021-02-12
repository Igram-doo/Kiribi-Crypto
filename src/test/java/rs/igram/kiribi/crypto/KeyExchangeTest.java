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
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import rs.igram.kiribi.io.*;

public class KeyExchangeTest {
	static final SecureRandom random = new SecureRandom();
	
	public static void random(byte[] bytes) {
		random.nextBytes(bytes);
	}

	public static int random(int bound) {
		return random.nextInt(bound);
	}

	public static long random() {
		return random.nextLong();
	}

   @Test
   public void testKeyExchange() throws IOException, InterruptedException {
   	   var pi1 = new PipedInputStream();
   	   var i1 = new VarInputStream(pi1);
   	   var pi2 = new PipedInputStream();
   	   var i2 = new VarInputStream(pi2);
   	   var po1 = new PipedOutputStream();
   	   var o1 = new VarOutputStream(po1);
   	   var po2 = new PipedOutputStream();
       var o2 = new VarOutputStream(po2);
       
       pi1.connect(po1);
       pi2.connect(po2);
       
       var e1 = new KeyExchange(false, ByteStream.stream(i1, o2));
       var e2 = new KeyExchange(ByteStream.stream(i2, o1));
       
       var test = new TestEncodable();
       var result = new TestEncodable[1];
       var e = new IOException[1];
       
       var t1 = new Thread(() -> { 
       	   try {
       	   	   e1.exchange();
       	   	   e1.write(test);
       	   } catch(IOException ex) {
       	   	   e[0] = ex;
       	   }
       });
       
       var t2 = new Thread(() -> {
       	   try {
       	   	   e2.exchange();
       	   	   result[0] = e2.read(TestEncodable::new);
       	   } catch(IOException ex) {
       	   	   e[0] = ex;
       	   }
       	   
       });
       
       t1.start();
       t2.start();
       t2.join();
       if(e[0] !=null) throw e[0];
       assertNotNull(result[0]);
       assertEquals(test, result[0]);
       assertFalse(test == result[0]);
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