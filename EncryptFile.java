import edu.rit.util.Hex;
import edu.rit.util.Packing;
import java.io.*;
/**
 * File: EncryptFile.java
 *   $Id$
 *   
 * Revisions:
 *   $Log$
 */

/**
 * @author Dominik Suwala <dxs9411@RiT.edu>
 * @date Mar 1, 2014
 */
public class EncryptFile extends Encrypt {
	
	private byte[][] keySchedule = new byte[101][8];
	private static int shuffle[] = // Shuffle table mapping byte re-location
			new int[8];
	static {
		shuffle[7] = 7;
		for( int i = 0; i < 7; i++ ) {
			shuffle[i] = i * 2 % 7;
		}
	}
	public void encrypt( byte[] text ) {
		
		// Packs the text into long
		long state = Packing.packLongBigEndian( text, 0 );
		
		// Perform 100 ARK1 rounds. On 101st subkey, XOR like usual, but exit
		// without performing the additional operations
		
		for( int round = 1; round <= 101; round++ ) {
			
///////////////////
// Perform round //
///////////////////
		// XOR the 64-bit input state with the 64-bit subkey.
		/*
			System.out.print( round + "\t\t" );
			System.out.print( Hex.toString( state ) + "\t" );
			System.out.print( Hex.toString( keyupper ) + "\t" );
		*/
			state ^= Packing.packLongBigEndian( keySchedule[ round - 1 ], 0 );
		// 101st subkey generated, leave the loop
			if( round == 101 ) {
				break;
			}
		// Divide the state into eight 8-bit unsigned bytes.
			byte[] unpacked = new byte[8]; // The unpacked 64-bit state
			Packing.unpackLongBigEndian( state, unpacked, 0 );
			
			// Transform each byte by an affine function.
			for( int i = 0; i < 8; i++ ) {
				unpacked[i] = ( byte ) ( ( 215 * ( unpacked[i] & 255 ) + 98 ) % 256 );
			}
			
			byte permuted[] = new byte[8];
		// Permute the bytes by a perfect shuffle.
			for( int i = 0; i < 8; i++ ) {
				permuted[ shuffle[i] ] = unpacked[ i ];
			}
			
			unpacked = permuted;
			
		// Mix each pair of bytes together by a mix function.
			for( int i = 0; i < 4; i++ ) {
				// x = unpacked[i * 2] 		( Left = x )
				// y = unpacked[i * 2 + 1]	( Right = y )
				unpacked[i * 2] = ( byte ) ( ( ( ( unpacked[i * 2] & 255 ) + ( unpacked[i * 2 + 1] & 255 ) ) ) % 256 );
				unpacked[i * 2 + 1] ^= unpacked[i * 2];
			}
		// Rejoin the bytes into the 64-bit output state.
			state = Packing.packLongBigEndian( unpacked, 0 );
			// System.out.println( Hex.toString( state ) );
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
		try {
			//myKey = Hex.toByteArray( args[0] );
			//message = Hex.toByteArray( args[1] );
		}
		// catch IO exception
		catch ( java.lang.IndexOutOfBoundsException e ) {
			System.err.println( "Illegal argument(s). Terminating." );
			System.exit( 1 );
		}
	// Check number of arguments
		if( args.length != 3 ) {
			System.err.print( "Incorrect number of arguments. Terminating." );
			System.err.print( "usage: java EncryptFile <key> <ptfile> <ctfile>" );
			System.err.println( "arguments are 16 byte HEX, filename, filename" );
			System.exit( 1 );
		}
	// Check key size
		if( args[0].length() != 32 ) {
			System.err.print( "Key length invalid. Terminating." );
			System.err.print( "usage: java Encrypt <key> <ptfile> <ctfile>" );
			System.err.println( "arguments are 16 byte HEX, 8 byte HEX" );
			System.exit( 1 );
		}
	// Check plaintext file input
		if( args[1].length() < 1) {
			System.err.print( "Plaintext file length invalid. Terminating." );
			System.err.println( "usage: java Encrypt <key> <ptfile> <ctfile>" );
			System.exit( 1 );
		}
	// Check ciphertext file input
		if( args[2].length() < 1) {
			System.err.print( "Ciphertext file length invalid. Terminating." );
			System.err.println( "usage: java Encrypt <key> <ptfile> <ctfile>" );
			System.exit( 1 );
		}
	// Read file, store in string "ptfile_str". Then, pad the end.
		String ptfile_str = "";
		// ptfile_str = READ FILE CONTENTS HERE
		
		File ptfile = new File( args[1] );
		// System.out.println( ptfile.length() );
		byte[] fileContents = new byte[ (int) ptfile.length() ];
		try {
			new FileInputStream( ptfile.getAbsolutePath() ).read( fileContents );
		}
		catch( FileNotFoundException e ) {
			System.err.printf( "The file \"%s\" can't be found.", args[1] );
			System.exit( 1 );
		} catch( IOException e ) {
			System.err.printf( "There was an error reading file \"%s.\"", args[1] );
			System.exit( 1 );
		} catch ( Exception e ) {
			System.err.printf( "An error has occured in trying to read from file \"%s\".", args[1] );
			e.printStackTrace();
			System.exit( 1 );
		}
		ptfile_str = Hex.toString( fileContents );
		int len = ( int ) Math.ceil( ( ptfile_str.length() / 16 ) ); // Total blocks with padding
		
		int beginPadIndex = ( ptfile_str.length() % 16 ) / 2; // Index in which to begin padding with 0x80{ [ 00 ]* }
		
		if( ptfile_str.length() == 0 ) {
			System.err.print( "The file is empty" );
			System.exit( 1 );
		}
		
		for( int i = beginPadIndex; i < 8; i++ ) {
			if( i != beginPadIndex )
				ptfile_str += "00";
			else
				ptfile_str += "80";
		}
		// String is now a multiple of 8, and includes the padding scheme.
		// Feed each block into the encryption function, appending each cipher
		// block to the output stream

		byte[] entireMessage = Hex.toByteArray( ptfile_str );
		BlockCipher cipher = new Encrypt();
		String encrypted = "";
		myKey = Hex.toByteArray( args[0] );
		cipher.setKey( myKey );
	// Encrypt each block
		for( int i = 0; i <= len; i++ ) {
			// string[i * 8] to string[i * 8 + 7] is fed in as the plaintext
			// Take code from test and use it here. append the result to str
			byte[] block = new byte[8];
			for( int b = 0; b < 8; b++ )
				block[b] = entireMessage[i * 8 + b];
			
			cipher.encrypt( block );
			encrypted += Hex.toString( block );
		}
		// System.out.print( encrypted );
		
		// Dump the file contents to <ctfile> (catch exceptions), close streams. Done.
		File ctfile = new File( args[2] );
		try {
			new FileOutputStream( ctfile.getAbsolutePath() ).write( Hex.toByteArray( encrypted ) );
		}
		catch( IOException e ) {
			System.err.printf( "There was an error writing file \"%s.\"\n", args[2] );
			System.exit( 1 );
		} catch ( Exception e ) {
			System.err.printf( "An error has occured in trying to write to file \"%s\".", args[2] );
			e.printStackTrace();
			System.exit( 1 );
		}
	}
}