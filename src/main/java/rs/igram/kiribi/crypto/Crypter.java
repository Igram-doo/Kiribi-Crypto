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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static java.nio.file.StandardOpenOption.*;

import static rs.igram.kiribi.io.ByteUtils.bytes;
import static rs.igram.kiribi.crypto.Crypto.Cipher;
import static rs.igram.kiribi.crypto.Hash.sha256;

/**
 * Interface supporting reading and writing of byte arrays.
 *
 * @author Michael Sargent
 */
class Crypter {
	// iv
	private static final byte[] v = bytes(1725714613,1062313406);
	
	private final Cipher encrypter;
	private final Cipher decrypter;
		
	/**
	 * Initializes a newly created <code>VarInputStream</code> object
	 * so that it reads from the provided <code>VarInput</code>.
	 *
	 * @param path The input stream to read from.
	 * @param pass text
	 * @throws GeneralSecurityException text
	 * @throws IOException text
	 */
	public Crypter(Path path, char[] pass) throws GeneralSecurityException, IOException {
		var secret = sha256(sha256(bytes(pass)));
		var hash = sha256(sha256(secret));
		
		if(Files.exists(path)){
			byte[] b = Files.readAllBytes(path);
			if(!Arrays.equals(b, hash)) throw new GeneralSecurityException("Invalid password");
		}else{
			Files.write(path, hash, CREATE_NEW, WRITE);
		}
		encrypter = Crypto.cipher();
		decrypter = Crypto.cipher();
		
		// kdf
		var key = Crypto.key(secret, v, 32);
		encrypter.init(key);
		decrypter.init(key);
	}
	
	/**
	 * Reads a byte array from the stream.
	 *
	 * @param b text
	 * @return The byte array read.
	 * @throws IOException text
	 */
	public byte[] encrypt(byte[] b) throws IOException {
		synchronized(encrypter) {
			try{
				
				//encrypter.reset();
				/*
				int M = b.length;
				int N = encrypter.getBlockSize();
				byte[] buf = new byte[((M / N) * N) + (2 * N)];
				System.arraycopy(b, 0, buf, 0, M);
				return encrypter.encrypt(buf);
				*/
				return encrypter.encrypt(b);
			}catch(Exception e){
				e.printStackTrace();
				throw new IOException(e);
			}
		}
	}
	
	/**
	 * Reads a byte array from the stream.
	 *
	 * @param b text
	 * @return The byte array read.
	 * @throws IOException text
	 */
	public byte[] decrypt(byte[] b) throws IOException {
		synchronized(decrypter) {
			try{
				//decrypter.reset();
				return decrypter.decrypt(b);
			}catch(Exception e){
				e.printStackTrace();
				throw new IOException(e);
			}
		}
	}
}
