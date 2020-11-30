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
 * Provides a generator for EC 25519  key pairs.
 *
 * @author Michael Sargent
 */
public final class KeyPairGenerator {
	private KeyPairGenerator() {}
			
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
}

