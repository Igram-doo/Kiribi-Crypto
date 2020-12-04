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
import java.security.PublicKey;
import java.util.Arrays;

import rs.igram.kiribi.io.Encodable;
import rs.igram.kiribi.io.VarInput;
import rs.igram.kiribi.io.VarOutput;

/**
 * An instance of this class represents a digital signature.
 *
 * @author Michael Sargent
 */
public final class Signature implements Encodable {
	final byte[] data;
	
	Signature(byte[] data) {
		this.data = data;
	}
	
	/**
	 * Initializes a newly created <code>Signature</code> object
	 * so that it reads from the provided <code>VarInput</code>.
	 *
	 * @param in The input stream to read from.
	 * @throws IOException if there was a problem reading from the provided 
	 * <code>VarInputStream</code>.
	 */
	public Signature(VarInput in) throws IOException {
		data = in.readBytes();
	}
		
	/**
	 * Verifies if this signature is associated with the provided byte array and public key.
	 *
	 * @param data The byte array associated with this signature.
	 * @param key The public key associated with this signature.
	 * @return <code>true</code> if this signature is associated with the provide byte array
	 * and public key, <code>false</code> otherwise. .
	 */
	public boolean verify(byte[] data, PublicKey key) {
		if (key instanceof EC25519PublicKey) {
			return Crypto.verify(this, data, ((EC25519PublicKey)key).material);
		} else {
			return false;
		}
	}
	
	@Override
	public void write(VarOutput out) throws IOException {
		out.writeBytes(data);
	}
	
	@Override
	public boolean equals(Object o){
		if(this == o) return true;
		if(o != null && o.getClass() == Signature.class){
			Signature sig = (Signature)o;
			return Arrays.equals(data, sig.data);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(data);
	}
}

