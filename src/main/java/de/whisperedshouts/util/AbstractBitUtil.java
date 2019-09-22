/**
 * 
 */
package de.whisperedshouts.util;

import java.util.Arrays;

/**
 * @author mario.ragucci
 *
 */
public abstract class AbstractBitUtil {
  /**
   * returns the bit representation of a byte
   * @param b the byte to represent
   * @return the bit representation
   */
  public static String getBinaryRepresentation(byte b) {
    return Integer.toBinaryString(b & 255 | 256).substring(1);
  }

  /**
   * returns a bitmask that was left shifted (=nulled) by size bit
   * 
   * @param size
   *          the bits to shift
   * @return the shifted bitmask
   */
  public static byte getLeftShiftEightBitMask(int size) {
    byte bitmask = getRightShiftEightBitMask(size);
    bitmask = (byte) ~bitmask;

    return bitmask;
  }
  
  /**
   * returns a bitmask that was right shifted (=nulled) by size bit
   * 
   * @param size
   *          the bits to shift
   * @return the shifted bitmask
   */
  public static byte getRightShiftEightBitMask(int size) {

    byte bitmask = 0;

    for (int i = 0; i < (8 - size); i++) {
      bitmask <<= 1;
      bitmask |= 1;
    }

    return bitmask;
  }

  /**
   * scans a byte array and removes newline characters.
   * also padds the array if it has not the proper length
   * @param byteArray the byte array to scan
   * @param bitModulator the modulo to use
   * @return a sanitized byte array
   */
  public static byte[] sanitizeArray(byte[] byteArray, int bitModulator) {
    byte[] result = null;
    byte[] sanitizedTempArray = new byte[byteArray.length];
    int sanitizedSize = 0;
    for (byte b : byteArray) {
      if((char)b == System.lineSeparator().getBytes()[0]) {
        continue;
      } else {
        sanitizedTempArray[sanitizedSize++] = b;
      }
    }
    result = Arrays.copyOf(sanitizedTempArray, sanitizedSize);
    
    // padding
    int paddingSize = bitModulator - (sanitizedSize % bitModulator);
    if(paddingSize != bitModulator) {
      result = Arrays.copyOf(sanitizedTempArray, sanitizedSize + paddingSize);
      for(int i = 1; i <= paddingSize; i++) {
        result[result.length - i] = '=';
      }
    }
    
    return result;
  }

  /**
   * shift a byte by the amount of bits, either rightshifted or not
   * 
   * @param b
   *          the byte to shift
   * @param bits
   *          the amount of bits to shift
   * @param rightshift
   *          whether to shift to the right
   * @return the shifted byte
   */
  public static byte shiftBits(byte b, int bits, boolean rightshift) {

    byte result = 0;
    if (rightshift) {
      result = b >>>= bits;
      result |= getRightShiftEightBitMask(bits);
    } else {
      result = b <<= bits;
      result |= getLeftShiftEightBitMask(bits);
    }

    return result;
  }
}
