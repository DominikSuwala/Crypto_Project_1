import edu.rit.util.Hex;
import edu.rit.util.Packing;

/**
 * File: Encrypt.java
 *   $Id$
 *   
 * Revisions:
 *   $Log$
 */

/**
 * @author Dominik Suwala <dxs9411@RiT.edu>
 * @date Mar 1, 2014
 * Parallel Java 2, Interface : Alan Kaminsky <ark@cs.rit.edu>
 */
public class Decrypt implements BlockCipher {
	
	private long keyupper; // Key bits 127..64 stored in keyupper bits 63..0.
	private long keylower; // Key bits 63..0 stored in keylower bits 63..0.
	// Store subkeys in schedule
	private byte[][] keySchedule = new byte[101][8];
	
	/**
    * Returns this block cipher's block size in bytes.
    *
    * @return  Block size.
    */
	public int blockSize() {
		return 8;
	}
	
	/**
	* Returns this block cipher's key size in bytes.
	*
	* @return  Key size.
	*/
	public int keySize() {
		return 16;
	}
	
	/**
    * Set the key for this block cipher. <TT>key</TT> must be an array of bytes
    * whose length is equal to <TT>keySize()</TT>.
    * <P>
    * For ARK1, bytes <TT>key[0]</TT> through <TT>key[15]</TT> are used.
    *
    * @param  key  Key.
    */
	public void setKey( byte[] key ) {
		keyupper = Packing.packLongBigEndian( key, 0 );
		keylower = Packing.packLongBigEndian( key, 8 );
		keySchedule = makeKeySchedule();
	}
	private static int shuffle[] = // Shuffle table mapping byte re-location
			new int[8];
	// Declare the permutation mapping
	static {
		shuffle[7] = 7;
		for( int i = 0; i < 7; i++ ) {
			shuffle[i] = i * 2 % 7;
		}
	}
	
	/**
	 * Makes the key schedule (subkeys)
	 * @return The key schedule
	 */
	public byte[][] makeKeySchedule() {
		
		byte[] unpacked_keyupper = new byte[8];
		byte[] unpacked_keylower = new byte[8];
		byte[][] keySched = new byte[101][8];
//////////////////
//Key schedule //
//////////////////
	for( int subkey = 1; subkey <= 101; subkey++ ) {
	// Rotate the 128-bit key state 25 bits to the right.
	// Key update.
	// Rotate right 25 bits
		long newku = 0x0000000000000000L;
		long newkl = 0x0000000000000000L;
	// Now we want to swap the 25 high-order bits of each number
		// 	Bit pattern:
		// 	Apply Mask
		// 	The mask ( to get the right-most 39 bits ):
		// 	b	00000000 00000000 00000000 01111111 11111111 11111111 11111111 11111111
		//  0x	00		 00		  00	   7F		 FF		  FF	   FF		FF
		// 	The mask ( to get the left-most 25 bits )
		//	b	11111111 11111111 11111111 10000000 00000000 00000000 00000000 00000000
		//	0x	FF		 FF		  FF	   80		 00		  00	   00		00
		keyupper = ( keyupper >>> 25 ) | ( keyupper << ( 64 - 25 ) );
		keylower = ( keylower >>> 25 ) | ( keylower << ( 64 - 25 ) );
		newku = 0x0000000000000000L;
		newkl = 0x0000000000000000L;
		
		newku |= ( ( 0x0000007FFFFFFFFFL ) & keyupper ); // Preserves right-most 39 bits
		newku |= ( ( 0xFFFFFF8000000000L ) & keylower ); // Moves high-order 25 bits from keylower to high-order 25 bits in keyupper
		
		newkl |= ( ( 0x0000007FFFFFFFFFL ) & keylower ); // Preserves right-most 39 bits
		newkl |= ( ( 0xFFFFFF8000000000L ) & keyupper ); // Moves high-order 25 bits from keyupper to high-order 25 bits in keylower
		
		keyupper = newku; // Saves keyupper
		keylower = newkl; // Saves keylower
		
	// Divide the key state into sixteen 8-bit _unsigned_ bytes.
		
		Packing.unpackLongBigEndian( keyupper, unpacked_keyupper, 0 );
		Packing.unpackLongBigEndian( keylower, unpacked_keylower, 0 );
	// Transform each of the eight most significant bytes by the affine
	// function A(x)
		for( int i = 0; i < 8; i++ ) {
			unpacked_keyupper[i] = ( byte ) ( ( 215 * ( unpacked_keyupper[i] & 255 ) + 98 ) % 256 );
		}
		
	// Permute the eight most significant bytes by a perfect shuffle.
	// Only operating on the first 64 bits.
		byte[] permuted_keyupper = new byte[8];
		for( int i = 0; i < 8; i++ ) {
			permuted_keyupper[ shuffle[i] ] = unpacked_keyupper[ i ];
		}
		
		unpacked_keyupper = permuted_keyupper;
		
	// Mix each pair of the eight most significant bytes together by
	// the mix function Mix (x, y)
		for( int i = 0; i < 4; i++ ) {
			// x = unpacked_keyupper[i * 2]
			// y = unpacked_keyupper[i * 2 + 1] = y ^ a
			unpacked_keyupper[i * 2] = ( byte )
					( ( ( unpacked_keyupper[i * 2] & 255 ) + ( unpacked_keyupper[i * 2 + 1] & 255 ) ) % 256 );
			unpacked_keyupper[i * 2 + 1] = ( byte ) ( ( unpacked_keyupper[i * 2 + 1] & 255 ) ^ ( unpacked_keyupper[i * 2] & 255 ) );
		}
		
	// Add (mod 256) the round number (1 for the first round, 2 for the
	// second round, etc.) to the least significant byte.
		unpacked_keylower[7] = ( byte ) ( ( ( unpacked_keylower[7] & 255 ) + subkey ) % 256 );
		
	// Rejoin the bytes into the 128-bit key state.
		keyupper = Packing.packLongBigEndian( unpacked_keyupper, 0 );
		keylower = Packing.packLongBigEndian( unpacked_keylower, 0 );
		
		Packing.unpackLongBigEndian( keyupper, keySched[ subkey - 1 ], 0 );
		// The 64 most significant bits of the key state are the subkey.
		// = keyupper. No extra code is needed
		
		// Perform 100 ARK1 rounds. On 101st subkey, XOR like usual, but exit
		// without performing the additional operations
	}	
		return keySched;
	}
	
	/**
    * Decrypt the given ciphertext. <TT>text</TT> must be an array of bytes
    * whose length is equal to <TT>blockSize()</TT>. On input, <TT>text</TT>
    * contains the ciphertext block. The ciphertext block is decrypted using the
    * key specified in the most recent call to <TT>setKey()</TT>. On output,
    * <TT>text</TT> contains the plaintext block.
    * <P>
    * For ARK1, bytes <TT>text[0]</TT> through <TT>text[7]</TT> are used.
    *
    * @param  text  Ciphertext (on input), plaintext (on output).
    */
	public void encrypt( byte[] text ) {
		
		// Packs the ciphertext into long
		long state = Packing.packLongBigEndian( text, 0 );
		
		// Track the key schedule to work backwards
		// 2D array. Index is subkeyNumber-1
		
//  /////////////// //
//  REVERSE ROUND!!
//  /////////////// //
		// XOR ( ciphertext ) ^ ( 101st subkey )
		// Then, run 100 rounds, backwards
		
		state ^= Packing.packLongBigEndian( keySchedule[100], 0 );
		
		for( int round = 100; round >= 1; round-- ) {
///////////////////////////////
// Perform rounds backwards ///
///////////////////////////////
		// Divide the state into eight 8-bit unsigned bytes.
			byte[] unpacked = new byte[8]; // The unpacked 64-bit state
			Packing.unpackLongBigEndian( state, unpacked, 0 );
			
			// Un-mix each pair of bytes together by inverse of mix function.
			for( int i = 0; i < 4; i++ ) {
				// Un-mix
				unpacked[i * 2 + 1] ^= unpacked[i * 2];
				unpacked[i * 2] = ( byte ) ( ( ( ( unpacked[i * 2] & 255 ) - ( unpacked[i * 2 + 1] & 255 ) ) ) % 256 );
			}
			
			// Unpermute the bytes by a perfect shuffle.
			byte permuted[] = new byte[8];
			for( int i = 0; i < 8; i++ ) {
				permuted[ i ] = unpacked[ shuffle[ i ] ];
			}
			unpacked = permuted;
			
			// Transform each byte by an affine function.
			for( int i = 0; i < 8; i++ ) {
				unpacked[i] = ( byte ) ( ( 231 * ( ( unpacked[i] & 255 ) - 98 ) ) % 256 );
			}
			
		// Rejoin the bytes into the 64-bit output state.
			state = Packing.packLongBigEndian( unpacked, 0 );
			// System.out.println( Hex.toString( state ) );
			long subkey = Packing.packLongBigEndian( keySchedule[ round - 1 ], 0 );
			state ^= subkey;
		}
		
		// The state output of round 100 is exclusive-ored with the 101st
		// subkey, and the result is the ciphertext
		Packing.unpackLongBigEndian( state, text, 0 );
		
	}
	/**
	 * @param args
	 * args[0] =  Key in HEX
	 * args[1] =  plaintext message in HEX to encrypt
	 */
	public static void main( String[] args ) {
		byte[] myKey = new byte[8];
		byte[] message = new byte[16];
		if( args.length != 2 ) {
			System.err.println( "Incorrect number of arguments. Terminating." );
			System.err.println( "usage: java Encrypt <key> <ciphertext>" );
			System.err.println( "arguments are 16 byte HEX, 8 byte HEX" );
			System.exit(1);
		}
		try {
			myKey = Hex.toByteArray( args[0] );
			message = Hex.toByteArray( args[1] );
		}
		catch ( java.lang.IndexOutOfBoundsException e ) {
			System.err.println( "Illegal argument(s). Terminating." );
			System.exit(1);
		}
	// Check key size
		if( args[0].length() != 32 ) {
			System.err.println( "Key length invalid. Terminating." );
			System.err.println( "usage: java Decrypt <key> <ciphertext>" );
			System.err.println( "arguments are 16 byte HEX, 8 byte HEX" );
			System.exit(1);
		}
	// Check plaintext size
		if( args[1].length() != 16 ) {
			System.err.println( "Plaintext length invalid. Terminating." );
			System.err.println( "usage: java Decrypt <key> <ciphertext>" );
			System.err.println( "arguments are 16 byte HEX, 8 byte HEX" );
			System.exit(1);
		}
		BlockCipher cipher = new Decrypt();
		cipher.setKey( myKey );
		byte[] plaintext = ( byte[] ) message.clone();
		cipher.encrypt( plaintext );
		System.out.println( Hex.toString( plaintext ) );
		
	}
}
