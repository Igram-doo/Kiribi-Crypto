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
import java.security.GeneralSecurityException;

import rs.igram.kiribi.io.ByteStream;
import rs.igram.kiribi.io.Decoder;
import rs.igram.kiribi.io.Encodable;
import rs.igram.kiribi.io.EncodedStream;

import static rs.igram.kiribi.crypto.Crypto.Cipher;
import static rs.igram.kiribi.crypto.Crypto.ECKeyPair;

/**
 * Provides a mechanism to exchange keys and read and write data.
 *
 * <p>An instance of this class can be in one of two modes depending on the value
 * of the <code>isProxing</code> property. If set to <code>false</code> the instance
 * will initiate the key exchange when the <code>exchange</code> method is called,
 * otherwise it will wait to receive the key from the other endpoint.</p>
 *
 * @author Michael Sargent
 */
public class KeyExchange implements EncodedStream {
	/**
	 * The <code>ByteStream</code> instance this <code>KeyExchange</code> instance
	 * uses to read from and write to.
	 */
	protected ByteStream stream;
	
	/**
	 * The mode of this <code>KeyExchange</code> object.
	 */
	protected final boolean isProxy;	

	private Cipher encrypter;
	private Cipher decrypter;
	private byte[] sk;
		
	/**
	 * Initializes a newly created <code>KeyExchange</code> object
	 * so that it reads froms and writes to the provided <code>ByteStream</code>.
	 *
	 * <p>The <code>KeyExchange</code> object is in proxy mode.</p>
	 *
	 * @param stream The input stream to read from and write to.
	 */
	public KeyExchange(ByteStream stream) {
		this(true, stream);
	}
			
	/**
	 * Initializes a newly created <code>VarInputStream</code> object
	 * so that it reads from the provided <code>VarInput</code>.
	 *
	 * @param isProxy Indicates whether the mode of this <code>KeyExchange</code> object.
	 * @param stream The input stream to read from and write to.
	 */
	public KeyExchange(boolean isProxy, ByteStream stream) {
		this.isProxy = isProxy;
		this.stream = stream;
	}

	// --- key exchange ---
	/**
	 * Performs the key exchange.
	 *
	 * <p><b>Note</b>: this method blocks until the key exchange completes or an error is thrown.</p>
	 *
	 * @throws IOException if there was a problem reading fromor writing to the underlying 
	 * <code>VarInputStream</code> during the key exchange.
	 */
	public void exchange() throws IOException {
		var pair = Crypto.generateECKeyPair();

		byte[] b;
		if(isProxy){
			writeKey(pair);
			b = readKey();
		}else{
			b = readKey();
			writeKey(pair);
		}
		try{
			sk = Crypto.agreement(pair, b);
			encrypter = Crypto.cipher();
			decrypter = Crypto.cipher();
		}catch(ArrayIndexOutOfBoundsException e){
			// thrown in Cypto.agreement
			throw new IOException("Key exchange failed", e);
		}
	}

	private byte[] readKey() throws IOException {
		return stream.read();
	}

	private void writeKey(ECKeyPair pair) throws IOException {
		var b = pair.pk;
		stream.write(b);
	}
	
	/**
	 * Encrypts a byte array.
	 *
	 * @param b The byte array to be encrypted.
	 * @return The encrypted byte array.
	 * @throws IOException if there was a problem encrypting the byte array.
	 * @throws IllegalStateException if this method was call before the key exchange was completed.
	 */
	public byte[] encrypt(byte[] b) throws IOException {
		if (encrypter == null) throw new IllegalStateException("Key exchange not complete");
		synchronized(encrypter) {
			try{
				encrypter.init(sk);
				var M = b.length;
				var N = encrypter.getBlockSize();
				var buf = new byte[((M / N) * N) + (2 * N)];
				System.arraycopy(b, 0, buf, 0, M);
				return encrypter.encrypt(buf);
			}catch(GeneralSecurityException e){
				throw new IOException(e);
			}
		}
	}
	
	/**
	 * Decrypts a byte array.
	 *
	 * @param b The byte array to be decrypted.
	 * @return The decrypted byte array.
	 * @throws IOException if there was a problem decrypting the byte array.
	 * @throws IllegalStateException if this method was call before the key exchange was completed.
	 */
	public byte[] decrypt(byte[] b) throws IOException {
		if (decrypter == null) throw new IllegalStateException("Key exchange not complete");
		synchronized(decrypter) {
			try{
				decrypter.init(sk);
				return decrypter.decrypt(b);
			}catch(GeneralSecurityException e){
				throw new IOException(e);
			}
		}
	}

	/**
	 * Writes an encodable object.
	 *
	 * @param data The encodable object to write.
	 * @throws IOException if there was a problem writing the data.
	 * @throws IllegalStateException if this method was call before the key exchange was completed.
	 */	
	@Override
	public void write(Encodable data) throws IOException {
		if (encrypter == null) throw new IllegalStateException("Key exchange not complete");
		var b = encrypt(data.encode());
		stream.write(b);
	}

	/**
	 * Reads an encodable object.
	 *
	 * @param <T> The type of the object to decode.
	 * @param decoder The decoder used to decode the object.
	 * @return The decoded object.
	 * @throws IllegalStateException if this method was call before the key exchange was completed.
	 */
	@Override
	public <T> T read(Decoder<T> decoder) throws IOException {
		if (decrypter == null) throw new IllegalStateException("Key exchange not complete");
		var b = stream.read();
		return decoder.decode(decrypt(b));
	}
}
