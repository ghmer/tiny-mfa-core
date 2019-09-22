/**
 * 
 */
package de.whisperedshouts.util;

import java.util.Arrays;

/**
 * RFC 3548 beschreibt die Kodierung beliebiger Binärdaten wie folgt: 
 * Fünf Bytes à 8-Bit (also zusammen 40 Bit) werden in acht 5-Bit-Gruppen zerlegt. 
 * Jede dieser Gruppen entspricht einer Zahl zwischen 0 und 31. 
 * Diese Zahlen werden anhand der nachfolgenden Umsetzungstabelle in 
 * „druckbare ASCII-Zeichen“ umgewandelt und ausgegeben. 
 * Wenn am Ende kein kompletter 40-Bit-Block mehr gebildet werden kann, wird dieser 
 * Block mit Nullbytes aufgefüllt und die 5-Bit-Gruppen, die nur aus Füllbits bestehen, 
 * mit = kodiert, um dem Dekodierer mitzuteilen, wie viele Füllbits hinzugefügt wurden.
 * 
 * @author mario.ragucci
 *
 */
public class Base32Util extends AbstractBitUtil {
  /**
   * the standard base32 characterset that is used to encode and decode base32
   */
  public static final String BASE32_CHARSET     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  /**
   * the alternate base32HEX characterset that i.E. is used in DNSSEC
   */
  public static final String BASE32_HEX_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

  /**
   * decodes a base32 encoded byte array. The characterset defined in RFC3548 is
   * used
   * 
   * @param byteArray
   *          the byte array to decode
   * @return the decoded byte array
   */
  public static byte[] decode(byte[] byteArray) {
    return decode(byteArray, Base32Util.BASE32_CHARSET);
  }
  
  /**
   * decodes a base32 encoded byte array with the characterset supplied
   * 
   * @param byteArray
   *          the byte array to decode
   * @param base32Charset
   *          the character set to use
   * @return the decoded byte array
   */
  public static byte[] decode(byte[] byteArray, String base32Charset) {
    byte[] tempArray = sanitizeArray(byteArray, 8);
    byte[] result = new byte[tempArray.length];
    int tempArrayPosition = 0;
    int resultArrayPosition = 0;

    while (tempArrayPosition < tempArray.length) {
      long number = 0;
      int[] resolvedBase32Chars = new int[8];
      int paddingCharacters = 0;
      for (int i = 0; i < 8; i++) {
        byte b = tempArray[tempArrayPosition++];
        resolvedBase32Chars[i] = base32Charset.indexOf(b);
        if ((char) b == '=') {
          paddingCharacters++;
        }

        // only the first 5 bits are of interest
        number += resolvedBase32Chars[i] & 0x1F;
        // if we are not the last byte of the queue, shift the number 5 bits to
        // the left
        if (i != 7) {
          number <<= 5;
        }
      }

      // create the 8 original bytes out of the 40bit number
      long b1 = (long) (number >> 32) & 0xFF;
      long b2 = (long) (number >> 24) & 0xFF;
      long b3 = (long) (number >> 16) & 0xFF;
      long b4 = (long) (number >>  8) & 0xFF;
      long b5 = (long) (number >>  0) & 0xFF;

      switch (paddingCharacters) {
        case 0:
          result[resultArrayPosition++] = (byte) b1;
          result[resultArrayPosition++] = (byte) b2;
          result[resultArrayPosition++] = (byte) b3;
          result[resultArrayPosition++] = (byte) b4;
          result[resultArrayPosition++] = (byte) b5;
          break;
        case 1:
          result[resultArrayPosition++] = (byte) b1;
          result[resultArrayPosition++] = (byte) b2;
          result[resultArrayPosition++] = (byte) b3;
          result[resultArrayPosition++] = (byte) b4;
          break;
        case 3:
          result[resultArrayPosition++] = (byte) b1;
          result[resultArrayPosition++] = (byte) b2;
          result[resultArrayPosition++] = (byte) b3;
          break;
        case 4:
          result[resultArrayPosition++] = (byte) b1;
          result[resultArrayPosition++] = (byte) b2;
          break;
        case 6:
          result[resultArrayPosition++] = (byte) b1;
          break;
      }
    }

    result = Arrays.copyOf(result, resultArrayPosition);

    return result;
  }
  

  /**
   * decodes a base32 encoded string. The characterset defined in RFC3548 is
   * used
   * 
   * @param base32Encoded
   *          the string to decode
   * @return the decoded byte array
   */
  public static byte[] decode(String base32Encoded) {
    return decode(base32Encoded.getBytes(), Base32Util.BASE32_CHARSET);
  }

  /**
   * decodes a base32 encoded string using the supplied character set
   * @param base32Encoded the string to decode
   * @param characterSet the character set to use
   * @return the decoded byte array
   */
  public static byte[] decode(String base32Encoded, String characterSet) {
    return decode(base32Encoded.getBytes(), characterSet);
  }

  /**
   * encodes a byte array to its base32 representation. The characterset defined
   * in RFC3548 is used
   * 
   * @param byteArray
   *          the byte array to encode
   * @return the encoded byte array
   */
  public static byte[] encode(byte[] byteArray) {
    return encode(byteArray, Base32Util.BASE32_CHARSET);
  }

  /**
   * encodes a byte array to its base32 representation with the characterset
   * supplied
   * 
   * @param byteArray
   *          the byte array to encode
   * @param base32Charset
   *          the characterset to use
   * @return the base32 encoded byte array
   */
  public static byte[] encode(byte[] byteArray, String base32Charset) {
    int paddedSize = byteArray.length % 5;

    byte[] resultArray = null;
    byte[] tempArray = null;
    if (paddedSize != 0) {
      tempArray = Arrays.copyOf(byteArray, byteArray.length + (5 - paddedSize));
    } else {
      tempArray = Arrays.copyOf(byteArray, byteArray.length);
    }

    resultArray = new byte[(tempArray.length / 5) * 8];
    int tempArrayPosition = 0;
    int resultArrayPosition = 0;

    while (tempArrayPosition < tempArray.length) {
      // generate a 40bit representation of the first 5 byte
      // take first byte
      long fourtyBytes = tempArray[tempArrayPosition++] & 0xFF;
      // shift 8 bits to the left
      fourtyBytes <<= 8;
      // take second byte
      fourtyBytes += tempArray[tempArrayPosition++] & 0xFF;
      // shift 8 bits to the left
      fourtyBytes <<= 8;
      // take third byte
      fourtyBytes += tempArray[tempArrayPosition++] & 0xFF;
      // shift 8 bits to the left
      fourtyBytes <<= 8;
      // take forth byte
      fourtyBytes += tempArray[tempArrayPosition++] & 0xFF;
      // shift 8 bits to the left
      fourtyBytes <<= 8;
      // take fifth byte
      fourtyBytes += tempArray[tempArrayPosition++] & 0xFF;

      // convert to 8 base32 characters
      for (int i = 0; i < 8; i++) {
        // how much to shift
        int shift = 35 - (i * 5);

        int n1 = (int) (fourtyBytes >> shift) & 0x1F;
        resultArray[resultArrayPosition++] = (byte) base32Charset.charAt(n1);

      }
    }

    // properly pad the last bytes
    switch (paddedSize) {
      case 1:
        for (int i = 1; i <= 6; i++) {
          resultArray[resultArray.length - i] = (byte) '=';
        }
        break;
      case 2:
        for (int i = 1; i <= 4; i++) {
          resultArray[resultArray.length - i] = (byte) '=';
        }
        break;
      case 3:
        for (int i = 1; i <= 3; i++) {
          resultArray[resultArray.length - i] = (byte) '=';
        }
        break;
      case 4:
        for (int i = 1; i <= 1; i++) {
          resultArray[resultArray.length - i] = (byte) '=';
        }
        break;
      default:
        break;
    }
    if (paddedSize > 0) {
      int padWidth = 5 - paddedSize;
      for (int i = 1; i <= padWidth; i++) {
        resultArray[resultArray.length - i] = (byte) '=';
      }
    }

    return resultArray;
  }
  
  /**
   * encodes a byte array to a base32 encoded string
   * @param byteArray the byte array to encode
   * @return the encoded String
   */
  public static String encodeToString(byte[] byteArray) {
    
    return new String(encode(byteArray));
  }
  
  /**
   * encodes a byte array to base32 using the supplied character set
   * @param byteArray the byte array to encode
   * @param characterSet the character set to use
   * @return the base32 encoded string
   */
  public static String encodeToString(byte[] byteArray, String characterSet) {
    
    return new String(encode(byteArray, characterSet));
  }
}
