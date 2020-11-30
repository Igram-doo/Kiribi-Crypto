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
 	private transient Address address;
 		
 	// need for serialization
 	private EC25519PublicKey() {super();}
 		
	/**
	 * Initializes a newly created <code>Key.Public</code> object
	 * from the provided byte array.
	 *
	 * @param material The byte array to initialize from.
	 */				
	public EC25519PublicKey(byte[] material) {
		super(material);
	}
		
	/**
	 * Initializes a newly created <code>Key.Public</code> object
	 * from the provided <code>String</code>.
	 *
	 * @param s The string to initialize from.
	 */			
	public EC25519PublicKey(String s) {
		super(s);
	}
		
	/**
	 * Initializes a newly created <code>Key.Public</code> object
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
	 * Returns the <code>Address</code> of the EC public key associated with this 
	 * <code>Key</code> object.
	 *
	 * @return Returns the <code>Address</code> of the EC public key associated with this 
	 * <code>Key</code> object.
	 */
	public Address address() {
		if (address == null) {
			address = new Address(ripemd160(sha256(material)));
		}
		return address;
	}
	
	/**
	 * Verifies if the provided signature is associated with the provided byte array and this key.
	 *
	 * @param signature The signature associated with this key and provided byte array.
	 * @param data The byte array associated with this key and provided signature.
	 * @return <code>true</code> if the provided signature is associated with the provide byte array
	 * and this key, <code>false</code> otherwise. .
	 * @throws IOException if there was a problem verifying the provided byte array.
	 */
	public boolean verify(Signature signature, byte[] data) throws IOException {
	 	return signature.verify(data, this);
	}

	 /**
	  * Verifies if the provided signed object is associated with the provided byte array and this key.
	  *
	  * @param signed The signed data associated with this key and provided byte array.
	  * @param data The byte array associated with this key and provided signed data.
	  * @return <code>true</code> if the provided signed data and byte array are associated with 
	  * this key, <code>false</code> otherwise. .
	  * @throws IOException if there was a problem verifying the provided signed data and byte array.
	  */
	 public boolean verify(SignedData signed, byte[] data) throws IOException {
	 	 return Arrays.equals(material, signed.getPublicKey().getEncoded()) 
	  	 && Arrays.equals(data, signed.data()) 
	  	 && signed.verify();
	 }

	@Override
	public boolean equals(Object o){
		if(this == o) return true;
		if(o != null && o.getClass() == Key.Public.class){
			Key.Public k = (Key.Public)o;
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
