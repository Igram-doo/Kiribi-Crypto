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

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Arrays;
import javax.crypto.SecretKey;

import rs.igram.kiribi.io.Encodable;
import rs.igram.kiribi.io.VarInput;
import rs.igram.kiribi.io.VarOutput;
import java.util.Base64;

import static rs.igram.kiribi.crypto.Crypto.ECKeyPair;
import static rs.igram.kiribi.crypto.Crypto.generateECKeyPair;
import static rs.igram.kiribi.crypto.Hash.ripemd160;
import static rs.igram.kiribi.crypto.Hash.sha256;

/**
 *
 * @author Michael Sargent
 */
abstract class EC25519PKey implements Encodable {
	public static final String ALGORITHM = "EC25519";
	transient byte[] material;// = new byte[0];
		
	// need for serialization
	EC25519PKey() {}
		
	EC25519PKey(byte[] material) {
		this.material = copy(material);
	}
		
	EC25519PKey(VarInput in) throws IOException {
		material = in.readBytes();
	}
	
	EC25519PKey(String s) {
		this(Base64.getUrlDecoder().decode(s));
	}
	
	@Override
	public final void write(VarOutput out) throws IOException {
		out.writeBytes(material);
	}
	
	public final String	getAlgorithm()	{
		return ALGORITHM;
	}
		
	public final byte[] getEncoded() {
		return copy(material);
	}
		
	public final String	getFormat() {
		return "RAW";
	}
		
	private static byte[] copy(byte[] src) {
		byte[] b = new byte[src.length];
		System.arraycopy(src, 0, b, 0, src.length);
		return b;
	}

	@Override
	public final int hashCode() {return Arrays.hashCode(material);}

	@Override
	public final String toString() {return Base64.getUrlEncoder().encodeToString(material);}
}

