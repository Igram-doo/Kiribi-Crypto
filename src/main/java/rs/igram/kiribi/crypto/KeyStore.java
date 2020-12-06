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
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Enumeration;
import javax.crypto.SecretKey;

import rs.igram.kiribi.io.Encodable;
import rs.igram.kiribi.io.VarInput;
import rs.igram.kiribi.io.VarOutput;

/**
 * An instance of this class represents a key store.
 *
 * @author Michael Sargent
 */
public final class KeyStore {
	private final java.security.KeyStore delegate;
	
	private KeyStore(java.security.KeyStore delegate) {
		this.delegate = delegate;
	}
	
	/**
	 * Returns a new <code>KeyStore</code> instance.
	 *
	 * @param password The password used to initialize the keystore, or null.
	 * @return A new <code>KeyStore</code> instance.
	 * @see load​(InputStream, char[])
	 * @see store
	 */  	
	public static KeyStore instance(char[] password) {
		try {
			java.security.KeyStore delegate = Crypto.getKeyStoreInstance(password);
			return new KeyStore(delegate);
		} catch(KeyStoreException e) {
			// shouldn't happen
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Returns a new <code>KeyStore</code> instance from a previously saved key store.
	 *
	 * @param stream The input stream from which the keystore is loaded.
	 * @param password The password used to check the integrity of the keystore, the password used to unlock the keystore, or null.
	 * @return A new <code>KeyStore</code> instance from a previously store key store.
	 * @throws KeyStoreException if there was a problem instantiating the key store.
	 * @throws IOException if there was an I/O problem with data.
	 * @see instance​
	 * @see store
	 */  	
	public static KeyStore load​(InputStream stream, char[] password) throws IOException, KeyStoreException {
		KeyStore keystore = instance(password);
		try {
			keystore.delegate.load​(stream, password);
			return keystore;
		} catch(NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		} catch(CertificateException e) {
			throw new KeyStoreException(e);
		}
	}	
	
	/**
	 * Lists all the alias names of this keystore.
	 *
	 * @return An enumeration of the alias names.
	 */  	
	public Enumeration<String> aliases() {
		try {
			return delegate.aliases();
		} catch(KeyStoreException e) {
			// shouldn't happen
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Checks if the given alias exists in this keystore.
	 *
	 * @param alias The byte array for which this method will generate a hash.
	 * @return <code>true</code> if the alias exists, <code>false</code> otherwise.
	 */  	
	public boolean containsAlias​(String alias) {
		try {
			return delegate.containsAlias​(alias);
		} catch(KeyStoreException e) {
			// shouldn't happen
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Deletes the entry identified by the given alias from this keystore.
	 *
	 * @param alias The alias name.
	 * @throws KeyStoreException if the entry cannot be removed.
	 */  	
	public void deleteEntry​(String alias) throws KeyStoreException {
		delegate.deleteEntry​(alias);
	}
	
	/**
	 * Retrieves the number of entries in this keystore.
	 *
	 * @return The number of entries in this keystore.
	 */  	
	public int size() {
		try {
			return delegate.size();
		} catch(KeyStoreException e) {
			// shouldn't happen
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Generates a key pair, stores it in the key store and returns the generated key pair.
	 *
	 * @param alias The alias name.
	 * @param password The password to generate the key pair integrity check.
	 * @return The generated key pair.
	 * @throws KeyStoreException if there was a problem generating the key pair or storing the key pair in the key store.
	 * @see getKeyPair
	 * @see deleteEntry
	 */  	
	public KeyPair generateKeyPair​(String alias, char[] password) throws KeyStoreException {
		return Crypto.generateKeyPair​(delegate, alias, password);
	}
		
	/**
	 * Returns the requested key pair.
	 *
	 * @param alias The alias name.
	 * @param password The password for recovering the key pair.
	 * @return The requested key pair, or null if the given alias does not exist or does not identify a key pair entry.
	 * @throws KeyStoreException if there was a problem recovering the key pair.
	 * @throws NullPointerException if alias is null.
	 * @see generateKeyPair
	 * @see deleteEntry
	 */  	
	public KeyPair getKeyPair​(String alias, char[] password) throws KeyStoreException {
		return Crypto.getKeyPair​(delegate, alias, password);
	}
	
	/**
	 * Generates a secret key, stores it in the key store and returns the generated key.
	 *
	 * @param alias The alias name.
	 * @param password The password to generate the key integrity check.
	 * @param size The size of the key to generate.
	 * @param algorthim The algorithm name of the key to generate.
	 * @return The generated key.
	 * @throws KeyStoreException if there was a problem generating the key or storing the key in the key store.
	 * @see getSecretKey
	 * @see deleteEntry
	 */  	
	public SecretKey generateSecretKey​(String alias, char[] password, int size, String algorthim) throws KeyStoreException {
		return Crypto.generateSecretKey​(delegate, alias, password, size, algorthim);
	}
	
	/**
	 * Returns the requested key.
	 *
	 * @param alias The alias name.
	 * @param password The password for recovering the key.
	 * @return The requested key, or null if the given alias does not exist or does not identify a key-related entry.
	 * @throws KeyStoreException if there was a problem recovering the key.
	 * @throws NullPointerException if alias is null.
	 * @see generateSecretKey
	 * @see deleteEntry
	 */  		
	public SecretKey getSecretKey​(String alias, char[] password) throws KeyStoreException {
		return Crypto.getSecretKey​(delegate, alias, password);
	}
	
	/**
	 * Stores this keystore to the given output stream, and protects its integrity with the given password.
	 *
	 * @param stream The output stream to which this keystore is written.
	 * @param password The password to generate the keystore integrity check.
	 * @throws KeyStoreException if there was a problem the keystore.
	 * @throws IOException if there was an I/O problem with data.
	 * @see instance
	 * @see load​(InputStream, char[])
	 */  	
	public void store​(OutputStream stream, char[] password) throws KeyStoreException, IOException {
		try {
			delegate.store​(stream, password);
		} catch(NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		} catch(CertificateException e) {
			throw new KeyStoreException(e);
		}
	}
}