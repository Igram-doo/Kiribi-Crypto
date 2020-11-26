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

import rs.igram.kiribi.io.Decoder;
import rs.igram.kiribi.io.Encodable;
import rs.igram.kiribi.io.VarInput;
import rs.igram.kiribi.io.VarOutput;

import static rs.igram.kiribi.crypto.Crypto.ECKeyPair;
import static rs.igram.kiribi.crypto.Hash.ripemd160;
import static rs.igram.kiribi.crypto.Hash.sha256;

/**
 * An instance of this class represents signed data.
 *
 * @see Key.Private#signData
 * @see Key.Public#verify​(SignedData, byte[])
 * @author Michael Sargent
 */
public final class SignedData implements Encodable {
	// data
	private final byte[] data;
	// public key
	private final byte[] pk;
	// signature
	private final Signature signature;
		
	SignedData(ECKeyPair pair, byte[] data) throws IOException {
		this.data = data;

		pk =  pair.pk;
		signature = Crypto.sign(pair, data);
	}
		
	/**
	 * Initializes a newly created <code>SignedData</code> object
	 * so that it reads from the provided <code>VarInput</code>.
	 *
	 * @param in The input stream to read from.
	 * @throws IOException if there was a problem reading from the provided 
	 * <code>VarInputStream</code>.
	 */
	public SignedData(VarInput in) throws IOException {
		data = in.readBytes();
		pk = in.readBytes();
		signature = new Signature(in);
	}
	
	@Override
	public void write(VarOutput out) throws IOException {
		out.writeBytes(data);
		out.writeBytes(pk);	
		signature.write(out);
	}
		
	/**
	 * The byte array contained in this signed object.
	 *
	 * @return The byte array contained in this object.
	 */
	public byte[] data() {return data;}
		
	/**
	 * The decoded data object contained in this signed object.
	 *
	 * @param <T> The type of the data object.
	 * @param decoder The <code>Decoder</code> used to decode the data object.
	 * @return The decoded data object.
	 * @throws IOException if there was a problem decoding the data object.
	 */
	public <T> T data(Decoder<T> decoder) throws IOException {
		return decoder.decode(data);
	}
		
	/**
	 * The public key associated with this signed object.
	 *
	 * @return The public key associated with this signed object.
	 */
	public PublicKey getPublicKey() {return new Key.Public(pk);}
	
	/**
	 * The <code>Address</code> associated with this signed object.
	 *
	 * @return The <code>Address</code> associated with this signed object.
	 * @see Address
	 */
	public Address address() {
		return new Address(ripemd160(sha256(pk)));
	}
	
	/**
	 * Verifies the validity of this signed object.
	 *
	 * @return <code>true</code> if this signed object is valid; <code>false</code> otherwise.
	 * @throws IOException if there was a problem verifying this signed data object.
	 */
	public boolean verify() throws IOException {
		return Crypto.verify(signature, data, pk);
	}

	@Override
	public boolean equals(Object o){
		if(this == o) return true;
		if(o != null && o.getClass() == SignedData.class){
			SignedData k = (SignedData)o;
			return signature.equals(k.signature)
				&& Arrays.equals(pk, k.pk)
				&& Arrays.equals(data, k.data);
		}
		return false;
	}

	@Override
	public int hashCode() {return signature.hashCode();}

	@Override
	public String toString() {return signature.toString();}
}

