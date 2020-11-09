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

import rs.igram.kiribi.io.Encodable;
import rs.igram.kiribi.io.VarInput;
import rs.igram.kiribi.io.VarOutput;
import java.util.Base64;

import static rs.igram.kiribi.crypto.Crypto.ECKeyPair;
import static rs.igram.kiribi.crypto.Crypto.generateECKeyPair;
import static rs.igram.kiribi.crypto.Hash.ripemd160;
import static rs.igram.kiribi.crypto.Hash.sha256;

/**
 * An instance of this class represents an EC key.
 *
 * @author Michael Sargent
 */
public final class Key implements Encodable {
	// 160 hash of public key
	private final byte[] hash;
	// public key
	private final byte[] pk;
	// key encoding (private key for bouncy castle) - null if public key
	private final byte[] encoded;
	// associated key - null if public key
	private final ECKeyPair pair;
	
	/**
	 * Initializes a newly created <code>Key</code> object
	 * so that it reads from the provided <code>VarInput</code>.
	 *
	 * @param in The input stream to read from.
	 * @throws IOException If there was a problem reading from the provided 
	 * <code>VarInputStream</code>.
	 */
	public Key(VarInput in) throws IOException {
		boolean isPublic = in.readBoolean();
		byte[] data = in.readBytes();
		if(isPublic){
			pk = data;
			encoded = null;
			pair = null;
		}else{
			encoded = data;
			pair = generateECKeyPair(encoded);
			pk =  pair.pk;
		}
		hash = ripemd160(sha256(pk));
	}

	private Key(byte[] pk){
		this.pk = pk;
		encoded = null;
		pair = null;
		hash = ripemd160(sha256(pk));
	}
		
	private Key(ECKeyPair pair){
		this.pair = pair;

		pk = pair.pk;
		encoded = pair.encoded;
		hash = ripemd160(sha256(pk));
	}
	
	@Override
	public void write(VarOutput out) throws IOException {
		out.writeBoolean(isPublic());
		byte[] data = isPublic() ? pk : encoded;
		out.writeBytes(data);
	}
	
	/**
	 * Returns the byte array of the EC public key associated with this <code>Key</code> object.
	 *
	 * @return Returns the byte array of the EC public key associated with this <code>Key</code> object.
	 */	
	public byte[] pk() {
		byte[] b = new byte[pk.length];
		System.arraycopy(pk, 0, b, 0, pk.length);
		return b;
	}
	
	/**
	 * Returns the EC public key associated with this <code>Key</code> object.
	 *
	 * @return Returns the EC public key associated with this <code>Key</code> object.
	 */	
	public Key pub() {
		return isPublic() ? this : new Key(pk);
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
	 * Indicates whether this <code>Key</code> object only contains a public EC key.
	 *
	 * @return The byte array read.
	 */
	public boolean isPublic() {return encoded == null;}
			
	/**
	 * Returns a <code>SignedData</code> object representing this <code>Key</code> object.
	 *
	 * @return Return a <code>SignedData</code> object representing this <code>Key</code> object.
	 * @throws IOException If there was a problem signing this key.
	 * @throws IllegalStateException If this key is a public key.
	 */
	public SignedData signedKey() throws IOException {
		if (pair == null) throw new IllegalStateException("Key is public");
		return new SignedData(pair, hash);
	}
	
	/**
	 * Returns a <code>SignedData</code> object associated with the provided byte array and
	 * this <code>Key</code> object.
	 *
	 * @param data The byte array to be signed.
	 * @return Returns a <code>SignedData</code> object associated with the provided byte array and
	 * this <code>Key</code> object.
	 * @throws IOException If there was a problem signing the provided byte array.
	 * @throws IllegalStateException If this key is a public key.
	 */
	public SignedData signData(byte[] data) throws IOException {
		if (pair == null) throw new IllegalStateException("Key is public");
		return new SignedData(pair, data);
	}
	
	/**
	 * Returns a <code>Signature</code> object associated with the provided byte array and
	 * this <code>Key</code> object.
	 *
	 * @param data The byte array for which the signature is to be generated.
	 * @return Returns a <code>Signature</code> object associated with the provided byte array and
	 * this <code>Key</code> object.
	 * @throws IOException If there was a problem generating the signature from the provided byte array.
	 * @throws IllegalStateException If this key is a public key.
	 */
	public Signature sign(byte[] data) throws IOException {
		if (pair == null) throw new IllegalStateException("Key is public");
		return Crypto.sign(pair, data);
	}
	
	/**
	 * Verifies if the provided signature is associated with the provided byte array and this key.
	 *
	 * @param signature The signature associated with this key and provided byte array.
	 * @param data The byte array associated with this key and provided signature.
	 * @return <code>true</code> if the provided signature is associated with the provide byte array
	 * and this key, <code>false</code> otherwise. .
	 * @throws IOException If there was a problem verifying the provided byte array.
	 */
	public boolean verify(Signature signature, byte[] data) throws IOException {
		return signature.verify(data, pk);
	}

	/**
	 * Verifies if the provided signed object is associated with the provided byte array and this key.
	 *
	 * @param signed The signed data associated with this key and provided byte array.
	 * @param data The byte array associated with this key and provided signed data.
	 * @return <code>true</code> if the provided signed data and byte array are associated with 
	 * this key, <code>false</code> otherwise. .
	 * @throws IOException If there was a problem verifying the provided signed data and byte array.
	 */
	public boolean verify(SignedData signed, byte[] data) throws IOException {
		return Arrays.equals(pk, signed.key()) 
			&& Arrays.equals(data, signed.data()) 
			&& signed.verify();
	}

	@Override
	public boolean equals(Object o){
		if(this == o) return true;
		if(o != null && o.getClass() == Key.class){
			Key k = (Key)o;
			return isPublic() == k.isPublic() 
				&& isPublic() ? Arrays.equals(pk, k.pk) : pair.equals(k.pair);
		}
		return false;
	}

	@Override
	public int hashCode() {return Arrays.hashCode(pk);}

	@Override
	public String toString() {return Base64.getUrlEncoder().encodeToString(pk);}
		
	/**
	 * Creates a new instance of a <code>Key</code>.
	 *
	 * <p><b>Note</b>: The newly created <code>Key</code> instance will only contain the public key.</p>
	 *
	 * @param pk The byte array used to generate this key instance.
	 * @return A new instance of a <code>Key</code>.
	 */
	public static Key publicKey(byte[] pk) {
		return new Key(pk);
	}
			
	/**
	 * Creates a new instance of a <code>Key</code>.
	 *
	 * <p><b>Note</b>: The newly created <code>Key</code> instance will only contain the public key.</p>
	 *
	 * @param pk The string used to generate this key instance.
	 * @return A new instance of a <code>Key</code>.
	 */
	public static Key publicKey(String pk) {
		return publicKey(Base64.getUrlDecoder().decode(pk));
	}
		
	/**
	 * Creates a new instance of a <code>Key</code>.
	 *
	 * <p><b>Note</b>: The newly created <code>Key</code> instance will contain the EC key pair
	 * an hence can be used to sign data.</p>
	 *
	 * @return A new instance of a <code>Key</code>.
	 */
	public static Key generate() {
		return new Key(generateECKeyPair());
	}
	
	/**
	 * Creates a new instance of a <code>Key</code>.
	 *
	 * <p><b>Note</b>: The newly created <code>Key</code> instance will contain the EC key pair
	 * an hence can be used to sign data.</p>
	 *
	 * @param pk The byte array used to generate this key instance.
	 * @return A new instance of a <code>Key</code>.
	 */
	public static Key generate(byte[] encoded) {
		return new Key(generateECKeyPair(encoded));
	}
}

