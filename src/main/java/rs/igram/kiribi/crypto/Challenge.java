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
 
/**
 * Interface supporting reading and writing of byte arrays.
 *
 * @author Michael Sargent
 */ 
package rs.igram.kiribi.crypto;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

import rs.igram.kiribi.crypto.Address;
import rs.igram.kiribi.crypto.Key;
import rs.igram.kiribi.crypto.Signature;
import rs.igram.kiribi.crypto.SignedData;
import rs.igram.kiribi.io.Encodable;
import rs.igram.kiribi.io.VarInput; 
import rs.igram.kiribi.io.VarOutput;

import static rs.igram.kiribi.crypto.Crypto.random;

/**
 * Interface supporting reading and writing of byte arrays.
 *
 */
final class Challenge implements Encodable {
	static final int SIZE = 16;
	private final byte[] b = new byte[SIZE];
	
	/**
	 * Initializes a newly created <code>VarInputStream</code> object
	 * so that it reads from the provided <code>VarInput</code>.
	 *
	 */
	public Challenge() {
		random(b);
	}
	
	/**
	 * Initializes a newly created <code>VarInputStream</code> object
	 * so that it reads from the provided <code>VarInput</code>.
	 *
	 * @param bytes The input stream to read from.
	 */
	public Challenge(byte[] bytes) {
		System.arraycopy(bytes, 0, b, 0, SIZE);
	}
		
	/**
	 * Initializes a newly created <code>VarInputStream</code> object
	 * so that it reads from the provided <code>VarInput</code>.
	 *
	 * @param in The input stream to read from.
	 * @throws IOException text
	 */
	public Challenge(VarInput in) throws IOException {
		in.readFully(b);
	}

	@Override
	public void write(VarOutput out) throws IOException {out.write(b);}
	
	/**
	 * Reads a byte array from the stream.
	 *
	 * @param data text
	 * @param address text
	 * @return The byte array read.
	 */
	public boolean verify(SignedData data, Address address) {
		try{
			return data.verify() && address.equals(data.address()) && Arrays.equals(b, data.data());
		}catch(IOException e){
			return false;
		}
	}
	
	/**
	 * Reads a byte array from the stream.
	 *
	 * @param sig text
	 * @param key text
	 * @return The byte array read.
	 */
	public boolean verify(Signature sig, Key key) {
		try{
			return key.verify(sig, b);
		}catch(IOException e){
			return false;
		}
	}
	
	@Override
	public byte[] encode() throws IOException {
		byte[] encoded = new byte[SIZE];
		System.arraycopy(b, 0, encoded, 0, SIZE);
		return encoded;
	}
	
	@Override
	public String toString(){return Base64.getEncoder().encodeToString(b);}

	@Override
	public int hashCode(){return Arrays.hashCode(b);}

	@Override
	public boolean equals(Object o){
		if(this == o) return true;
		if(o == null || o.getClass() != Challenge.class) return false;
		return Arrays.equals(b, ((Challenge)o).b);
	}
}
