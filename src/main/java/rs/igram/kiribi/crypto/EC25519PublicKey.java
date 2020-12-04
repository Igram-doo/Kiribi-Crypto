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
 * An instance of this class represents a public EC 25519 key.
 *
 * @author Michael Sargent
 */
public final class EC25519PublicKey extends EC25519PKey implements PublicKey {
 	private static final long serialVersionUID = 1L;
 	private transient byte[] hash;
 		
 	// need for serialization
 	private EC25519PublicKey() {super();}
 		
	/**
	 * Initializes a newly created <code>EC25519PublicKey</code> object
	 * from the provided byte array.
	 *
	 * @param material The byte array to initialize from.
	 */				
	public EC25519PublicKey(byte[] material) {
		super(material);
	}
		
	/**
	 * Initializes a newly created <code>EC25519PublicKey</code> object
	 * from the provided <code>String</code>.
	 *
	 * @param s The string to initialize from.
	 */			
	public EC25519PublicKey(String s) {
		super(s);
	}
		
	/**
	 * Initializes a newly created <code>EC25519PublicKey</code> object
	 * so that it reads from the provided <code>VarInput</code>.
	 *
	 * @param in The input stream to read from.
	 * @throws IOException if there was a problem reading from the provided 
	 * <code>VarInputStream</code>.
	 */		
	public EC25519PublicKey(VarInput in) throws IOException {
		super(in);
	}
			
	/**
	 * Returns a crypto-graphic hash of this public key.
	 *
	 * @return Returns a crypto-graphic hash of this public key.
	 */
	byte[] hash() {
		if (hash == null) {
			hash = ripemd160(sha256(material));
		}
		return hash;
	}

	@Override
	public boolean equals(Object o){
		if(this == o) return true;
		if(o != null && o.getClass() == EC25519PublicKey.class){
			EC25519PublicKey k = (EC25519PublicKey)o;
			return Arrays.equals(material, k.material);
		}
		return false;
	}		
		
	private void writeObject(ObjectOutputStream oos) throws IOException {
		oos.defaultWriteObject();
		oos.writeInt(material.length);
		oos.write(material);
	}
 
    private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException {
       	ois.defaultReadObject();
       	int l = ois.readInt();
       	material = new byte[l];
       	ois.read(material);
    }
}

