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

import java.security.SecureRandom;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * Interface supporting reading and writing of byte arrays.
 *
 * @author Michael Sargent
 */
final class Crypto {
	private static final CryptoSpi spi = new Curve25519Provider();
	static final SecureRandom random;

 	static {
		try{
			random = SecureRandom.getInstance("SHA1PRNG", "SUN"); 
		}catch(Exception e){
			throw new RuntimeException("Could not initialize secure random",e);
		}
	}
	
	/**
	 * Reads a byte array from the stream.
	 *
	 * @param bytes text
	 */	
	static void random(byte[] bytes) {
		random.nextBytes(bytes);
	}
	
	/**
	 * Reads a byte array from the stream.
	 *
	 * @param bound text
	 * @return The byte array read.
	 */
	static int random(int bound) {
		return random.nextInt(bound);
	}
	
	/**
	 * Reads a byte array from the stream.
	 *
	 * @return The byte array read.
	 */
	static long random() {
		return random.nextLong();
	}

	// convenience method
		
	/**
	 * Reads a byte array from the stream.
	 */
	public static void gen() {
		ECKeyPair p = generateECKeyPair();
		int[] e = rs.igram.kiribi.crypto.ByteUtils.ints(p.encoded);
		for(int i = 0; i < e.length; i++) System.out.println(""+e[i]);
		System.out.println(Base64.getEncoder().encodeToString(p.pk));
	}
	
	static byte[] key(byte[] secret, byte[]  iv, int len) {
		return spi.key(secret, iv, len);
	}
	
	static ECKeyPair generateECKeyPair() {
		return spi.generateECKeyPair();
	}
	
	static ECKeyPair generateECKeyPair(byte[] encoded) {
		return spi.generateECKeyPair(encoded);
	}

	static byte[] agreement(ECKeyPair pair, byte[] key) {
		return spi.agreement(pair, key);
	}
	
	static Signature sign(ECKeyPair pair, byte[] data) {
		return spi.sign(pair, data);
	}
	
	static boolean verify(Signature sig, byte[] data, byte[] pk) {
		return spi.verify(sig, data, pk);
	}
	
	static Cipher cipher() {
		return spi.cipher();
	}
	
	static abstract class Cipher {
		abstract void init(byte[] key);
		abstract int getBlockSize();
		abstract byte[] encrypt(byte[] b) throws GeneralSecurityException;
		abstract byte[] decrypt(byte[] b) throws GeneralSecurityException;
		abstract void reset();
	}

	static class ECKeyPair {
		final byte[] pk;
		final byte[] encoded;
		
		ECKeyPair(byte[] pk, byte[] encoded) {
			this.pk = pk;
			this.encoded = encoded;
		}
	}
	
	static abstract class CryptoSpi {
		abstract Cipher cipher();
		abstract byte[] key(byte[] secret, byte[]  iv, int len);
		abstract ECKeyPair generateECKeyPair();
		abstract ECKeyPair generateECKeyPair(byte[] encoded);
		abstract byte[] agreement(ECKeyPair pair, byte[] key);
		abstract Signature sign(ECKeyPair pair, byte[] data);
		abstract boolean verify(Signature sig, byte[] data, byte[] pk);
	}
}

