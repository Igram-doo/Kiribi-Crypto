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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class contains static utility methods to generate cryptographic hashes.
 *
 * @author Michael Sargent
 */
abstract class Hash {
 	private Hash() {}
	
	/**
	 * Returns a sha256 hash.
	 *
	 * @param data The byte array for which this method will generate a hash.
	 * @return The hash of the byte array.
	 */        
    public static final byte[] sha256(byte[] data) {
    	try{
    		return MessageDigest.getInstance("SHA-256").digest(data);
    	}catch(NoSuchAlgorithmException e){
    		// sha256 is required to be supported
    		throw new RuntimeException(e);
    	}
    }
         
    // cheat - just take the first 20 bytes of sha256; rename later..
	/**
	 * Returns a truncated sha256 hash.
	 *
	 * @param data The byte array for which this method will generate a hash.
	 * @return The hash of the byte array.
	 */
    public static final byte[] ripemd160(byte[] data) {
    	byte[] sha256 = sha256(data);
    	byte[] result = new byte[20];
    	System.arraycopy(sha256, 0, result, 0, 20);
    	return result;
//       	return hash(new RIPEMD160Digest(), data);
    }
}
