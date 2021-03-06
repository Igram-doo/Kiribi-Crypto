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
import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import javax.crypto.spec.SecretKeySpec;

import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import rs.igram.kiribi.io.VarInputStream;
import rs.igram.kiribi.io.VarOutputStream;

import static java.security.KeyStore.*;
import static javax.crypto.Cipher.*;

import static rs.igram.kiribi.crypto.Crypto.Cipher;
import static rs.igram.kiribi.crypto.Crypto.ECKeyPair;
import static rs.igram.kiribi.crypto.Hash.sha256;
import static rs.igram.kiribi.io.ByteUtils.bytes;
import static rs.igram.kiribi.io.ByteUtils.concat;
import static rs.igram.kiribi.io.ByteUtils.crop;
import static rs.igram.kiribi.io.ByteUtils.extract;
import static rs.igram.kiribi.io.ByteUtils.xor;

/**
 * Package private class.
 *
 * @author Michael Sargent
 */
final class Curve25519Provider extends Crypto.CryptoSpi {
	// aes key size
	private static final int AES_KEY_SIZE = 16; 
	// iv
	private static final byte[] v = bytes(743419265,1221901279);
			
	@Override
	java.security.KeyStore getKeyStoreInstance(char[] password) throws KeyStoreException {
		try {
			var keystore = java.security.KeyStore.getInstance("JCEKS");
			keystore.load(null, password);
			return keystore;
		} catch(IOException e) {
			// shouldn'' happen
			throw new RuntimeException(e);
		} catch(NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		} catch(CertificateException e) {
			throw new KeyStoreException(e);
		}
	}
		
	@Override
	KeyPair generateKeyPair​(java.security.KeyStore keystore, String alias, char[] password) throws KeyStoreException {
		var pair = generateECKeyPair();
		put(pair.encoded, alias, password, keystore);
		return pair.toEC25519KeyPair();
	}
		
	@Override
	KeyPair getKeyPair​(java.security.KeyStore keystore, String alias, char[] password) throws KeyStoreException {
		var key = get(alias, password, keystore);
		return key == null ? null :  key.generateKeyPair();
	}
	
	@Override
	SecretKey generateSecretKey​(java.security.KeyStore keystore, String alias, char[] password, int size, String algorthim) throws KeyStoreException {
		var b = new byte[size];
		Crypto.random(b);
		var spec = new SecretKeySpec(b, algorthim);		
		keystore.setEntry(alias, new SecretKeyEntry(spec), new PasswordProtection(password));
		return spec;
	}
	
	@Override
	SecretKey getSecretKey​(java.security.KeyStore keystore, String alias, char[] password) throws KeyStoreException {
		try {
			var entry = (SecretKeyEntry)keystore.getEntry(alias, new PasswordProtection(password));
			return entry == null ? null : 
				(entry.getSecretKey().getAlgorithm().equals("25519") ? 
					null  :
					entry.getSecretKey());
		} catch(NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		} catch(UnrecoverableEntryException e) {
			throw new KeyStoreException(e);
		}
	}

	private void put(byte[] key, String alias, char[] pw, java.security.KeyStore keystore) throws KeyStoreException {
		var spec = new SecretKeySpec(key, "25519");		
		keystore.setEntry(alias, new SecretKeyEntry(spec), new PasswordProtection(pw));	
	}

	private EC25519PrivateKey get(String alias, char[] pw, java.security.KeyStore keystore) throws KeyStoreException {
		try {
			var entry = (SecretKeyEntry)keystore.getEntry(alias, new PasswordProtection(pw));
			return entry == null ? null : 
				(entry.getSecretKey().getAlgorithm().equals("25519") ? 
					new EC25519PrivateKey(entry.getSecretKey().getEncoded()) :
					null);
		} catch(NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		} catch(UnrecoverableEntryException e) {
			throw new KeyStoreException(e);
		}
	}

	@Override
	ECKeyPair generateECKeyPair() {
		var encoded = new byte[32];
		Crypto.random(encoded);
		encoded = sha256(encoded);
		
		return generateECKeyPair(encoded);
	}
	
	@Override
	ECKeyPair generateECKeyPair(byte[] encoded) {
		var p = new byte[32];
		var s = new byte[32];
		var k = new byte[32];
		System.arraycopy(encoded, 0, k, 0, 32);
		Curve25519.keygen(p, s, k);
		
		return new Pair(s, k, p, encoded);
	}

	@Override
	byte[] agreement(ECKeyPair pair, byte[] key) {
		var z = new byte[32];
		Curve25519.curve(z, ((Pair)pair).k, key);
		
		return key(z, v, 32);
	}
	
	@Override
	Signature sign(ECKeyPair pair, byte[] data) {
		var p = (Pair)pair;
		var s = p.s;
		var P = p.pk;
		var Z = P;
		
		var m = sha256(concat(P, data));
		var x = sha256(concat(m, s));
		var Y = new byte[32];
		Curve25519.keygen(Y, null, x);
		var r = sha256(Y);
		var h = xor(m, r, 32);
		var v = new byte[32];
		Curve25519.sign(v, h, x, s);
		
		return new Signature(concat(v, r));
	}
	
	@Override
	boolean verify(Signature sig, byte[] data, byte[] pk) {
		var v = extract(sig.data, 0, 32);
		var r = extract(sig.data, 32, 32);
		
		var m = sha256(concat(pk, data));
		var h = xor(m, r, 32);
		var Y = new byte[32];
		Curve25519.verify(Y, v, h, pk);
		
		return Arrays.equals(r, sha256(Y));
	}
	
	@Override
	Cipher cipher() {
		return new AESCipher();
	}
	
	private static final class AESCipher extends Cipher {
		private static final String AES = "AES";
		private static final String ALGORITHM = "AES/GCM/NoPadding";
		private static final int LEN_TAG = 128;
		private static final int LEN_NONCE = 12;
		private final SecureRandom secureRandom = new SecureRandom();
		private final javax.crypto.Cipher cipher;
		private SecretKeySpec spec;

		AESCipher() {
			try{
				cipher = javax.crypto.Cipher.getInstance(ALGORITHM, "SunJCE");
			}catch(Exception e){
				throw new RuntimeException("Cipher not available: "+ALGORITHM);
			}
		}
		
		@Override
		void init(byte[] key) {
			var sk = crop(key, AES_KEY_SIZE);
			spec = new SecretKeySpec(sk, AES);
		}
		
		@Override
		int getBlockSize() {
			return cipher.getBlockSize();
		}
		
		@Override
		byte[] encrypt(byte[] b) throws GeneralSecurityException {		
			try{
				var nonce = new byte[LEN_NONCE];
				secureRandom.nextBytes(nonce);
				cipher.init(ENCRYPT_MODE, spec, new GCMParameterSpec(LEN_TAG, nonce));
				var encrypted = cipher.doFinal(b);

				var byteBuffer = ByteBuffer.allocate(LEN_NONCE + encrypted.length);
				byteBuffer.put(nonce);
				byteBuffer.put(encrypted);

				return byteBuffer.array();
			}catch(Exception e){
				throw new GeneralSecurityException("Encryption failed", e);
			}
		}

		@Override
		byte[] decrypt(byte[] b) throws GeneralSecurityException {		
			try {
				var byteBuffer = ByteBuffer.wrap(b);
				var nonce = new byte[LEN_NONCE];
				byteBuffer.get(nonce);
				var encrypted = new byte[b.length - LEN_NONCE];
				byteBuffer.get(encrypted);
				cipher.init(DECRYPT_MODE, spec, new GCMParameterSpec(LEN_TAG, nonce));
				var decrypted = cipher.doFinal(encrypted);
				return decrypted;
			} catch (Exception e) {
				throw new GeneralSecurityException("Decryption failed", e);
			}
		}

		@Override
		void reset() {
			throw new UnsupportedOperationException("Cipher reset not supported");
		}
	}
	
	private static class Pair extends ECKeyPair {
		final byte[] s;
		final byte[] k;
		
		Pair(byte[] s, byte[] k, byte[] pk, byte[] encoded) {
			super(pk, encoded);
			this.s = s;
			this.k = k;
		}
	}	
}

