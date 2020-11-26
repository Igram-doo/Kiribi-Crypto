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
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import rs.igram.kiribi.io.Encodable;
import rs.igram.kiribi.io.VarInput;
import rs.igram.kiribi.io.VarOutput;
import java.util.Base64;

import static rs.igram.kiribi.crypto.Crypto.ECKeyPair;
import static rs.igram.kiribi.crypto.Crypto.generateECKeyPair;
import static rs.igram.kiribi.crypto.Hash.ripemd160;
import static rs.igram.kiribi.crypto.Hash.sha256;

/**
 * Provides a generator for EC 25519  key pairs.
 *
 * @see Address
 * @see Signature
 * @see SignedData
 * @author Michael Sargent
 */
public final class Key {
	private Key() {}
			
	/**
	 * Creates a new instance of a <code>KeyPair</code>.
	 *
	 * <p><b>Note</b>: The newly created <code>KeyPair</code> instance will contain the EC 25519 key pair
	 * an hence can be used to sign data.</p>
	 *
	 * @return A new instance of a <code>KeyPair</code>.
	 */
	public static KeyPair generateKeyPair() {
		return generateECKeyPair().toKeyPair();
	}
	
	static void checkType(KeyPair pair) throws IllegalArgumentException {
		if (!(pair.getPublic() instanceof Key.Public) || !(pair.getPrivate() instanceof Key.Private)) {
			throw new IllegalArgumentException("Illegal Key type");
		}
	}
	
	static class AbstractKey implements Encodable {
		public static final String ALGORITHM = "EC25519";
		byte[] material;
		
		AbstractKey(byte[] material) {
			this.material = copy(material);
		}
		
		AbstractKey(VarInput in) throws IOException {
			material = in.readBytes();
		}
	
		AbstractKey(String s) {
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
			return null;
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
	
	/**
	 * An instance of this class represents a public EC 25519 key.
 	 */		
 	public static final class Public extends AbstractKey implements PublicKey {
		// hash of public key
		final byte[] hash;
		
		/**
		 * Initializes a newly created <code>Key.Public</code> object
		 * from the provided byte array.
		 *
		 * @param material The byte array to initialize from.
		 */				
		public Public(byte[] material) {
			super(material);
			hash = ripemd160(sha256(material));
		}
		
		/**
		 * Initializes a newly created <code>Key.Public</code> object
		 * from the provided <code>String</code>.
		 *
		 * @param s The string to initialize from.
		 */			
		public Public(String s) {
			super(s);
			hash = ripemd160(sha256(material));
		}
		
		/**
		 * Initializes a newly created <code>Key.Public</code> object
		 * so that it reads from the provided <code>VarInput</code>.
		 *
		 * @param in The input stream to read from.
		 * @throws IOException if there was a problem reading from the provided 
		 * <code>VarInputStream</code>.
		 */		
		public Public(VarInput in) throws IOException {
			super(in);
			hash = ripemd160(sha256(material));
		}
				
		/**
		 * Returns the <code>Address</code> of the EC public key associated with this 
		 * <code>Key</code> object.
		 *
		 * @return Returns the <code>Address</code> of the EC public key associated with this 
		 * <code>Key</code> object.
		 */
		public Address address() {
			return new Address(hash);
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
	}
	
	/**
	 * An instance of this class represents a private EC 25519 key.
 	 */		
	public static final class Private extends AbstractKey implements PrivateKey {
		private ECKeyPair pair;
		
		/**
		 * Initializes a newly created <code>Key.Private</code> object
		 * from the provided byte array.
		 *
		 * @param material The byte array to initialize from.
		 * byte array.
		 */				
		public Private(byte[] material) {
			super(material);
		}
		
		/**
		 * Initializes a newly created <code>Key.Private</code> object
		 * from the provided <code>String</code>.
		 *
		 * @param s The string to initialize from.
		 */			
		public Private(String s) {
			super(s);
		}
	
		/**
		 * Initializes a newly created <code>Key.Private</code> object
		 * so that it reads from the provided <code>VarInput</code>.
		 *
		 * @param in The input stream to read from.
		 * @throws IOException if there was a problem reading from the provided 
		 * <code>VarInputStream</code>.
		 */		
		public Private(VarInput in) throws IOException {
			super(in);
		}
	
		/**
		 * Creates an instance of a <code>KeyPair</code> containing this private key and its associated public key.
		 *
		 * @return A new instance of a <code>KeyPair</code> containing this private key and its associated public key.
		 */
		public KeyPair generateKeyPair() {
			return pair().toKeyPair();
		}
			
		/**
		 * Returns a <code>SignedData</code> object representing this <code>Key</code> object.
		 *
		 * @return Return a <code>SignedData</code> object representing this <code>Key</code> object.
		 * @throws IOException if there was a problem signing this key.
		 */
		public SignedData signedKey() throws IOException {
			ECKeyPair pair = pair();
			byte[] hash = ripemd160(sha256(pair.pk));
			return new SignedData(pair, hash);
		}
	
		/**
		 * Returns a <code>SignedData</code> object associated with the provided byte array and
		 * this <code>Key</code> object.
		 *
		 * @param data The byte array to be signed.
		 * @return Returns a <code>SignedData</code> object associated with the provided byte array and
		 * this <code>Key</code> object.
		 * @throws IOException if there was a problem signing the provided byte array.
		 */
		public SignedData signData(byte[] data) throws IOException {
		 	return new SignedData(pair(), data);
		}
	
		/**
		 * Returns a <code>Signature</code> object associated with the provided byte array and
		 * this <code>Key</code> object.
		 *
		 * @param data The byte array for which the signature is to be generated.
		 * @return Returns a <code>Signature</code> object associated with the provided byte array and
		 * this <code>Key</code> object.
		 * @throws IOException if there was a problem generating the signature from the provided byte array.
		 */
		public Signature sign(byte[] data) throws IOException {
			return Crypto.sign(pair(), data);
		}

		/**
		 * Return the <code>Address</code> associated with this private key's public key.
		 *
		 * @return Returns the <code>Address</code> associated with this private key's public key.
		 */
		public Address address() {
			byte[] pk = pair().pk;
			byte[] hash = ripemd160(sha256(pk));
			return new Address(hash);
		}
		
		private ECKeyPair pair() {
			if (pair == null) {
				pair = generateECKeyPair(material);
			}
			return pair;
		}
		
		@Override
		public boolean equals(Object o){
			if(this == o) return true;
			if(o != null && o.getClass() == Key.Private.class){
				Key.Private k = (Key.Private)o;
				return Arrays.equals(material, k.material);
			}
			return false;
		}
	}
}

