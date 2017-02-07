import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import edu.rit.util.Hex;
import edu.rit.util.Packing;

/**
 * File: DecryptFile.java
 *   $Id$
 *   
 * Revisions:
 *   $Log$
 */

/**
 * @author Dominik Suwala <dxs9411@RiT.edu>
 * @date Mar 1, 2014
 */
public class DecryptFile extends Decrypt {

	/**
	 * 
	 */
	// Store subkeys in schedule
	private byte[][] keySchedule = new byte[101][8];
	
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
	 * args[1] =  ciphertext file in HEX to decrypt
	 * args[2] =  plaintext file in HEX that holds decrypted contents
	 * Size of plaintext file will be at least one byte smaller, due to padding
	 */
	public static void main( String[] args ) {
		byte[] myKey = new byte[8];
	// Check argument count
		if( args.length != 3 ) {
			System.err.print( "Invalid number of arguments. Terminating." );
			System.err.print( "usage: java Encrypt <key> <ctfile> <ptfile>" );
			System.err.println( "arguments are 16 byte HEX, filename, filename" );
			System.exit( 1 );
		}
		
		// Check key size
		if( args[0].length() != 32 ) {
			System.err.print( "Key length invalid. Terminating." );
			System.err.print( "usage: java Encrypt <key> <ctfile> <ptfile>" );
			System.err.println( "arguments are 16 byte HEX, 8 byte HEX" );
			System.exit( 1 );
		}
		// Check ciphertext file input
		if( args[1].length() < 1) {
			System.err.print( "Ciphertext file length invalid. Terminating." );
			System.err.println( "usage: java Encrypt <key> <ctfile> <ptfile>" );
			System.exit( 1 );
		}
		// Check plaintext file input
		if( args[2].length() < 1) {
			System.err.print( "Plaintext file length invalid. Terminating." );
			System.err.println( "usage: java Encrypt <key> <ctfile> <ptfile>" );
			System.exit( 1 );
		}
		
		
	// Set key
		try {
			myKey = Hex.toByteArray( args[0] );
		}
	// Supplied key is not HEX, or error parsing
		catch ( Exception e ) {
			System.err.println( "Illegal argument(s). Terminating. Ensure that <key> is in HEX." );
			System.exit( 1 );
		}
	// Check key size
		if( args[0].length() != 32 ) {
			System.err.print( "Key length invalid. Terminating." );
			System.err.print( "usage: java Decrypt <key> <ctfile> <ptfile>" );
			System.err.println( "arguments are 16 byte HEX, filename, filename" );
			System.exit( 1 );
		}
		
	// Read the CTfile in. Check if its length is ( > 0 ) and ( 0 MOD 8 )
		String ctfile_str = "";
		File ctfile = new File( args[1] );
		
		if( ctfile.length() == 0 ) {
			System.err.println( "File is empty. Exiting" );
			System.exit( 1 );
		}
	// Check if the file is a multiple of 8 bytes
		else if( ctfile.length() % 8 != 0 ) {
			System.err.println( "The input file's length is not a multiple of 8 bytes!" );
			System.exit( 1 );
		}
	// File length is fine, proceed
		byte[] fileContents = new byte[ (int) ctfile.length() ];
		try {
			new FileInputStream( ctfile.getAbsolutePath() ).read( fileContents );
		}
		catch( FileNotFoundException e ) {
			System.err.printf( "The file \"%s\" can't be found.%n", args[1] );
			System.exit( 1 );
		} catch( IOException e ) {
			System.err.printf( "There was an error reading file \"%s.\"%n", args[1] );
			System.exit( 1 );
		} catch ( Exception e ) {
			System.err.printf( "An error has occured in trying to read from file \"%s\".%n", args[1] );
			e.printStackTrace();
			System.exit( 1 );
		}
		ctfile_str = Hex.toString( fileContents );
		// System.out.println( "Incoming: \n" + ctfile_str );
		byte[] entireMessage = Hex.toByteArray( ctfile_str );
		
		BlockCipher cipher = new Decrypt();
		cipher.setKey( myKey );
		
		// Run the decryption algorithm per block, then strip off the padding.
		// Repack the new string into bytes. Output to new ptfile.
		
		String decrypted = "";
	// Number of blocks	
		long len = ctfile.length() / 8;
		// System.out.println( entireMessage.length );
	// Decrypt each block
		for( int i = 0; i < len; i++ ) {
			// string[i * 8] to string[i * 8 + 7] is fed in as the ciphertext
			// Append the result to hex_str
			byte[] block = new byte[8];
			for( int b = 0; b < 8; b++ )
				block[b] = entireMessage[i * 8 + b];
			cipher.encrypt( block );
			decrypted += Hex.toString( block );
		}
		// System.out.println( decrypted );
		
	// Verify that the padding is LEGAL. Throw error if not.
	// Legal messages will have 0x 80 and, optionally
	// { 0x00 } until message is multiple of 8 bytes, padded on the end
	// (aka: message is complete and key is correct)
	// If padding is legal, strip the padding before saving PTfile
		
	// Either the last byte of the last block is 0x80
	// -or-
	// Last block contains 0x80 followed by any number of 0x00
		// System.out.println( ( decrypted.length() ) );
		String lastBlock = decrypted.substring( decrypted.length() - 16, decrypted.length() );
		// System.out.println( lastBlock );
		
		byte[] lastBlockByteArray = Hex.toByteArray( lastBlock );
		
		// Check for first instance of padding 0x80.
		//	if i == 7 and the padding is 0x80, the padding is 1 byte
		//  otherwise, check that the successive bytes are 0x00 from i at 0x80
		// until i = 7
		boolean reached80 = false;
		boolean legal = false;
		int removeIndex = -1;
		for( int i = 0; i < 8; i++ ) {
			// Read first occurrence of 0x80
			if( !reached80 ) {
				if( lastBlockByteArray[i] == ( byte ) 0x80 ) {
					reached80 = true;
					legal = true;
					removeIndex = i;
				}
			}
			// We reached 0x80. We will read 00s from now on. Falsify if we
			// reach a non 0x00
			else {
				if( lastBlockByteArray[i] != ( byte ) 0x00 ) {
					legal = false;
					break;
				}
			}
		}
	// Strip padding if padding is legal
		if( legal ) {
			decrypted = decrypted.substring( 0, decrypted.length() - ( 2 * ( 8 - removeIndex ) ) );
		}
		else {
			System.err.print( "Illegal padding. Exiting." );
			System.exit( 1 );
		}
		// System.out.println( decrypted );
		
		// Dump the file contents to <ptfile> (catch exceptions), close streams. Done.
		File ptfile = new File( args[2] );
		try {
			new FileOutputStream( ptfile.getAbsolutePath() ).write( Hex.toByteArray( decrypted ) );
		}
		catch( IOException e ) {
			System.err.printf( "There was an error writing file \"%s.\"%n", args[2] );
			System.exit( 1 );
		} catch ( Exception e ) {
			System.err.printf( "An error has occured in trying to write to file \"%s\".%n", args[2] );
			e.printStackTrace();
			System.exit( 1 );
		}
	}
}
