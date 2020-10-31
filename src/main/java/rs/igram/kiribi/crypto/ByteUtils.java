package rs.igram.kiribi.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.IntBuffer;
import java.util.Arrays;
import java.util.List;

/**
 * Pacage private utilities class.
 *
 * @author Michael Sargent
 */
abstract class ByteUtils {	
	public static byte[] reverse(byte[] b) {
		final int l = b.length;
		final byte[] buf = new byte[l];
		for (int i = 0; i < l; i++) buf[i] = b[l - 1 - i];
		return buf;
	}

	public static byte[] concat(byte[]... chunks) {
		try{
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			for(byte[] chunk : chunks) baos.write(chunk);
			return baos.toByteArray();
		}catch(IOException e){
			// shouldn't happen
			throw new RuntimeException("WTF");
		}
	}

	public static byte[] concat(List<byte[]> chunks){
		try{
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			for(byte[] chunk : chunks) baos.write(chunk);
			return baos.toByteArray();
		}catch(IOException e){
			// shouldn't happen
			throw new RuntimeException("WTF");
		}
	}

	public static void or(byte[] a, byte[] b, int L){
		for(int i = 0; i < L; i++) a[i] |= b[i];
	}

	public static void and(byte[] a, byte[] b, int L){
		for(int i = 0; i < L; i++) a[i] &= b[i];
	}
	
	public static byte[] xor(byte[] a, byte[] b, int L){
		byte[] c = new byte[L];
		for(int i = 0; i < L; i++) c[i] = (byte)(a[i] ^ b[i]);
		return c;
	}

	// a & b = b
	public static boolean matches(byte[] a, byte[] b, int L){
		for(int i = 0; i < L; i++) if((a[i] & b[i]) != b[i]) return false;
		return true;
	}

	public static byte[] crop(byte[] data, int L){
		final byte[] b = new byte[L];
		System.arraycopy(data, 0, b, 0, L);
		return b;
	}
		
	public static int varSize(long v) {
		if(v < 0l) throw new IllegalArgumentException("Input must be non-negative: "+v);
		if(v < 0xFD) return 1;
		if(v <= 0xFFFF) return 2;
		if(v <= 0xFFFFFFFF) return 4;
		return 8;
	}
	
	public static void put(byte[] b, int pos, int v) {
		ByteBuffer buf = ByteBuffer.wrap(b);
		buf.putInt(pos, v);
	}
	
	public static void put(byte[] b, int pos, long v) {
		ByteBuffer buf = ByteBuffer.wrap(b);
		buf.putLong(pos, v);
	}

	public static byte[] longToBytes(long v) {
		byte[] b = new byte[8];
		put(b, 0, v);
		return b;
	}
	
	public static long bytesToLong(byte[] b) {
		return getLong(b, 0);
	}
	
	public static int getInt(byte[] b, int pos) {
		ByteBuffer buf = ByteBuffer.wrap(b);
		return buf.getInt(pos);
	}
	
	public static long getLong(byte[] b, int pos) {
		ByteBuffer buf = ByteBuffer.wrap(b);
		return buf.getLong(pos);
	}
	
	public static void inet(byte[] b, int offset, SocketAddress address) throws Exception {
		InetSocketAddress inet = ((InetSocketAddress)address);
		if(inet.getAddress() instanceof Inet6Address){
			System.arraycopy(inet.getAddress().getAddress(), 0, b, offset, 16);
		}else{
			b[offset] = (byte)0xff;
			b[offset + 1] = (byte)0xff;
			System.arraycopy(inet.getAddress().getAddress(), 0, b, offset + 2, 4);
			for(int i = offset + 6; i < offset + 16; i++) b[i] = 0;
		}
		put(b, offset + 16, inet.getPort());
	}
	
		
	public static SocketAddress inet(byte[] src, int offset) throws Exception {
		byte[] inet = null;
		if(src[offset] == (byte)0xff && src[offset + 1] == (byte)0xff){
			inet = extract(src, offset + 2, 4);
		}else{
			inet = extract(src, offset, 16);
		}
		InetAddress add = InetAddress.getByAddress(inet);
		int port = getInt(src, offset + 16);
		return new InetSocketAddress(add, port);
	}
		
	public static byte[] extract(byte[] src, int pos, int length) {
		byte[] dst = new byte[length];
		System.arraycopy(src, pos, dst, 0, length);
		return dst;
	}
	
	// unsigned int as long
	public static void unsignedIntToBytes(long l, byte[] buf, int offset) {
        buf[offset] = (byte) ((l & 0xFF000000L) >>> 24);
        buf[offset + 1] = (byte) ((l & 0x00FF0000L) >>> 16);
        buf[offset + 2] = (byte) ((l & 0x0000FF00L) >>> 8);
        buf[offset + 3] = (byte) ((l & 0x000000FFL));
    }

	// unsigned int as long
	public static byte[] unsignedIntToBytes(long l) {
		byte[] b = new byte[4];
		unsignedIntToBytes(l, b, 0);
		return b;
    }
    
    public static long bytesToUnsignedInt(byte[] buf, int offset) {
    	int l1, l2, l3, l4;
    	l1 = (0x000000FF & ((int)buf[offset]));
        l2 = (0x000000FF & ((int)buf[offset+1]));
        l3 = (0x000000FF & ((int)buf[offset+2]));
        l4 = (0x000000FF & ((int)buf[offset+3]));
        
        long l= ((long) (l1 << 24 | l2 << 16 | l3 << 8 | l4)) & 0xFFFFFFFFL;
        return l;
    }
    
    public static int[] ints(byte[] b) {
    	if(b.length % 4 != 0) throw new IllegalArgumentException();
    	IntBuffer buf =  ByteBuffer.wrap(b).asIntBuffer();
    	int L = b.length / 4;
    	int[] ints = new int[L];
    	for(int i = 0; i < L; i++) ints[i] = buf.get();
    	return ints;
    }
    
    public static byte[] bytes(char... chars) {
    	ByteBuffer buf = ByteBuffer.allocate(2 * chars.length);
    	for(int i = 0; i < chars.length; i++){
    		buf.putChar(chars[i]);
    	}
    	
    	return buf.array();
    }
    
    public static byte[] bytes(int... ints) {
    	ByteBuffer buf = ByteBuffer.allocate(4 * ints.length);
    	for(int i = 0; i < ints.length; i++){
    		buf.putInt(ints[i]);
    	}
    	
    	return buf.array();
    }
    
    public static CharSequence charseq(int... ints) {
    	ByteBuffer buf = ByteBuffer.allocate(4 * ints.length);
    	for(int i = 0; i < ints.length; i++){
    		buf.putInt(ints[i]);
    	}
    	
    	return buf.asCharBuffer();
    }

    public static char[] chars(int... ints) {
    	ByteBuffer buf = ByteBuffer.allocate(4 * ints.length);
    	for(int i = 0; i < ints.length; i++){
    		buf.putInt(ints[i]);
    	}
    	
    	CharBuffer cb = buf.asCharBuffer();
    	
    	int L = cb.length();
    	char[] chars = new char[L];
    	for(int i = 0; i < L; i++) chars[i] = cb.get();
    	return chars;
    }
}
