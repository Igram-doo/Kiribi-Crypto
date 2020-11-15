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
import java.util.Arrays;
import java.util.Base64;

import rs.igram.kiribi.io.Encodable;
import rs.igram.kiribi.io.VarInput;
import rs.igram.kiribi.io.VarOutput;

/**
 * An instance of this class represents an "Address" associated with a public key.
 *
 * @author Michael Sargent
 */
public final class Address implements Encodable {
	/**
	 * An "empty" address.
	 */
	public static final Address NULL = new Address(new byte[20]);
	
	/**
	 * text
	 */
	final byte[] bytes;
	
	/**
	 * Initializes a newly created <code>Address</code> object
	 * with a byte array.
	 *
	 * @param hash160 The byte array to initialize from.
	 */
	public Address(byte[] hash160){
		if(hash160.length != 20) throw new IllegalArgumentException("Input array wrong size: "+hash160.length);
		bytes = hash160;
	}
	
	/**
	 * Initializes a newly created <code>Address</code> object
	 * so that it reads from the provided <code>VarInput</code>.
	 *
	 * @param in The input stream to read from.
	 * @throws IOException If there was a problem reading from the provided 
	 * <code>VarInputStream</code>.
	 */
	public Address(VarInput in) throws IOException {
		bytes = new byte[20];
		in.readFully(bytes);
	}
	
	/**
	 * Initializes a newly created <code>VarInputStream</code> object
	 * from the provided string.
	 *
	 * @param s The string to initialize from.
	 */
	public Address(String s) {
		this(Base64.getUrlDecoder().decode(s));
	}

	@Override
	public void write(VarOutput out) throws IOException {
		out.write(bytes);
	}
		
	@Override
	public String toString() {return Base64.getUrlEncoder().encodeToString(bytes);}

	@Override
	public int hashCode() {return Arrays.hashCode(bytes);}

	@Override
	public boolean equals(Object o){
		if(this == o) return true;
		if(o != null && o.getClass() == Address.class){
			Address a = (Address)o;
			return Arrays.equals(bytes, a.bytes);
		}
		return false;
	}
}

