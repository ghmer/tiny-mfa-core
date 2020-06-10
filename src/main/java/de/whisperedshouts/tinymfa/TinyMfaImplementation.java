/**
 * 
 */

package de.whisperedshouts.tinymfa;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import de.whisperedshouts.util.Base32Util;

/**
 * This is an implementation of a time based one time pad (totp)
 * 
 * 
 * @author Mario Enrico Ragucci, mario@whisperedshouts.de
 * @version 1.0
 *
 */
public class TinyMfaImplementation {

    // a logger object. Make use of it!
    private static final Logger _logger = Logger.getLogger(TinyMfaImplementation.class.getName());

    // this is the default, static width used in the dynamic truncation
    public static final int DYNAMIC_TRUNCATION_WIDTH = 4;

    // that big is our key to be
    public static final int FINAL_SECRET_SIZE = 16;

    // this is the algorithm that is used to generate the rfc2104hmac hexstring
    public static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    // Indicator to not use an offset
    public static final int OFFSET_PRESENT = 0;

    // Indicator whether to apply an offset 30 seconds in the past for creating
    // the message
    public static final int OFFSET_PAST = 1;

    // Indicator whether to apply an offset 30 seconds into the future for
    // creating the message
    public static final int OFFSET_FUTURE = 2;

    /**
     * Calculates the hmac hash and returns its byteArray representation
     * 
     * @param data
     *            the message to hash (usually a timestamp)
     * @param key
     *            the secretKey to use
     * @return the byteArray representation of the calculated hmac
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private static byte[] calculateRFC2104HMAC(byte[] data, byte[] key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("ENTERING method %s(data %s, key %s)", "calculateRFC2104HMAC", data, key));
        }
        byte[] result = null;
        SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA1_ALGORITHM);
        Mac messageAuthCode = Mac.getInstance(HMAC_SHA1_ALGORITHM);

        messageAuthCode.init(signingKey);
        result = messageAuthCode.doFinal(data);

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("LEAVING method %s (returns: %s)", "calculateRFC2104HMAC", result));
        }
        return result;
    }

    /**
     * Generates a new secretKey and encodes it to base32
     * 
     * @return the byte array representation of the base32 encoded secret key
     */
    public static byte[] generateBase32EncodedSecretKeyByteArray() {
        if (_logger.isLoggable(Level.FINE)) {
            _logger.fine(String.format("ENTERING method %s()", "generateBase32EncodedSecretKeyByteArray"));
        }
        // Allocating the buffer
        byte[] buffer = new byte[128];

        // Filling the buffer with random numbers.
        new Random().nextBytes(buffer);

        // Getting the key and converting it to Base32
        byte[] secretKey = Arrays.copyOf(buffer, TinyMfaImplementation.FINAL_SECRET_SIZE);
        byte[] bEncodedKey = Base32Util.encode(secretKey);

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("LEAVING method %s (returns: %s)", "generateBase32EncodedSecretKeyByteArray",
                    bEncodedKey));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("LEAVING method %s (returns: %s)", "generateBase32EncodedSecretKeyByteArray",
                        "***"));
            }
        }

        return bEncodedKey;
    }

    /**
     * Generates a new secretKey and encodes it to base32
     * 
     * @return the base32 encoded secretKey
     */
    @Deprecated
    public static String generateBase32EncodedSecretKey() {
        if (_logger.isLoggable(Level.FINE)) {
            _logger.fine(String.format("ENTERING method %s()", "generateBase32EncodedSecretKey"));
        }

        byte[] bEncodedKey = generateBase32EncodedSecretKeyByteArray();
        String encodedKey = new String(bEncodedKey);

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(
                    String.format("LEAVING method %s (returns: %s)", "generateBase32EncodedSecretKey", bEncodedKey));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("LEAVING method %s (returns: %s)", "generateBase32EncodedSecretKey", "***"));
            }
        }

        return encodedKey;
    }

    public static char[] generateBase32EncodedSecretKeyCharArray() {
        if (_logger.isLoggable(Level.FINE)) {
            _logger.fine(String.format("ENTERING method %s()", "generateBase32EncodedSecretKeyCharArray"));
        }

        byte[] bEncodedKey = generateBase32EncodedSecretKeyByteArray();
        char[] encodedKey = byteArrayToCharArray(bEncodedKey);

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("LEAVING method %s (returns: %s)", "generateBase32EncodedSecretKeyCharArray",
                    encodedKey));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("LEAVING method %s (returns: %s)", "generateBase32EncodedSecretKeyCharArray",
                        "***"));
            }
        }

        return encodedKey;
    }

    /**
     * generates a valid token for a timestamp and a base32 encoded secretKey
     * 
     * @param message
     *            the timestamp to use when calculating the token
     * @param base32SecretKey
     *            the base32 encoded secretKey
     * @return the current valid token for this key
     * @throws Exception
     *             when we hit an issue
     */
    @Deprecated
    public static int generateValidToken(Long message, String base32SecretKey) throws Exception {
        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("ENTERING method %s(message %s, base32SecretKey %s)", "generateValidToken",
                    message, base32SecretKey));
        } else
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("ENTERING method %s(message %s, base32SecretKey %s)", "generateValidToken",
                        message, "***"));
            }
        int token = 0;
        try {

            byte[] keyByteArray = base32SecretKey.getBytes();
            token = generateValidToken(message, keyByteArray);

        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            _logger.severe(e.getMessage());
            throw new Exception(e.getMessage());
        }

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("LEAVING method %s (returns: %s)", "generateValidToken", token));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("LEAVING method %s (returns: %s)", "generateValidToken", "***"));
            }
        }

        return token;
    }

    /**
     * generates a valid token for a timestamp and a base32 encoded secretKey
     * 
     * @param message
     *            the timestamp to use when calculating the token
     * @param base32SecretKey
     *            the base32 encoded secretKey
     * @return the current valid token for this key
     * @throws Exception
     *             when we hit an issue
     */
    public static int generateValidToken(Long message, char[] base32SecretKey) throws Exception {
        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("ENTERING method %s(message %s, base32SecretKey %s)", "generateValidToken",
                    message, base32SecretKey));
        } else
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("ENTERING method %s(message %s, base32SecretKey %s)", "generateValidToken",
                        message, "***"));
            }
        int token = 0;
        try {

            byte[] keyByteArray = charArrayToByteArray(base32SecretKey);
            token = generateValidToken(message, keyByteArray);

        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            _logger.severe(e.getMessage());
            throw new Exception(e.getMessage());
        }

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("LEAVING method %s (returns: %s)", "generateValidToken", token));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("LEAVING method %s (returns: %s)", "generateValidToken", "***"));
            }
        }

        return token;
    }

    /**
     * generates a valid token for a timestamp and a base32 encoded secretKey
     * 
     * @param message
     *            the timestamp to use when calculating the token
     * @param base32SecretKey
     *            the base32 encoded secretKey as byte array
     * @return the current valid token for this key
     * @throws Exception
     *             when we hit an issue
     */
    public static int generateValidToken(Long message, byte[] base32SecretKey) throws Exception {
        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("ENTERING method %s(message %s, base32SecretKey %s)", "generateValidToken",
                    message, base32SecretKey));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("ENTERING method %s(message %s, base32SecretKey %s)", "generateValidToken",
                        message, "***"));
            }
        }

        int token = 0;
        byte[] keyBytes = null;
        byte[] messageBytes = null;
        // let's process
        try {
            // the key is base32 encoded
            keyBytes = Base32Util.decode(base32SecretKey);
            // get an 8byte array derived from the message
            messageBytes = TinyMfaImplementation.longToByteArray(message);
            // generate the rfc2104hmac String out of timestamp and key
            byte[] rfc2104hmac = TinyMfaImplementation.calculateRFC2104HMAC(messageBytes, keyBytes);

            // get the decimal representation of the last byte
            // this will be used as a offset. i.E if the last byte was 4 (as
            // decimal),
            // we will derive the dynamic trunacted result, starting at the 4th
            // index of the byte array
            int offset = rfc2104hmac[(rfc2104hmac.length - 1)] & 0xF;
            if (_logger.isLoggable(Level.FINEST)) {
                _logger.finest(String.format("using offset %d for dynamic truncation", (int) offset));
            }
            // probably int is too small (since there is no unsigned integer)
            // therefore, a long variable is used
            long dynamicTruncatedResult = 0;
            for (int i = 0; i < DYNAMIC_TRUNCATION_WIDTH; ++i) {
                // shift 8bit to the left to make room for the next byte
                dynamicTruncatedResult <<= 8;
                // perform a bitwise inclusive OR on the next offset
                // this adds the next digit to the dynamic truncated result
                dynamicTruncatedResult |= (rfc2104hmac[offset + i] & 0xFF);
            }

            // setting the most significant bit to 0
            dynamicTruncatedResult &= 0x7FFFFFFF;
            // making sure we get the right amount of numbers
            dynamicTruncatedResult %= 1000000;

            token = (int) dynamicTruncatedResult;

        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            _logger.severe(e.getMessage());
            throw new Exception(e.getMessage());
        }

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("LEAVING method %s (returns: %s)", "generateValidToken", token));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("LEAVING method %s (returns: %s)", "generateValidToken", "***"));
            }
        }

        return token;
    }

    /**
     * returns a message based on a "corrected timestamp" This method will get
     * the current system time (Milliseconds since 1970), then remove the
     * seconds elapsed since the last half minute (i.E. 34 becomes 30). Last, we
     * divide this by 30.
     * 
     * @return the message
     */
    public static long getValidMessageBySystemTimestamp() {
        if (_logger.isLoggable(Level.FINE)) {
            _logger.fine(String.format("ENTERING method %s()", "getValidMessageBySystemTimestamp"));
        }

        long message = getValidMessageBySystemTimestamp(OFFSET_PRESENT);

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(
                    String.format("LEAVING method %s (returns: %s)", "getValidMessageBySystemTimestamp", message));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(
                        String.format("LEAVING method %s (returns: %s)", "getValidMessageBySystemTimestamp", "***"));
            }
        }

        return message;
    }

    /**
     * * returns a message based on a "corrected timestamp" This method will get
     * the current system time (Milliseconds since 1970), then remove the
     * seconds elapsed since the last half minute (i.E. 34 becomes 30). Last, we
     * divide this by 30.
     * 
     * @param offsetType
     *            the type of offset to apply. You can use the static integers
     *            OFFSET_PRESENT, OFFSET_PAST and OFFSET_FUTURE.
     * @return the message
     */
    public static long getValidMessageBySystemTimestamp(int offsetType) {
        if (_logger.isLoggable(Level.FINE)) {
            _logger.fine(
                    String.format("ENTERING method %s(offsetType %s)", "getValidMessageBySystemTimestamp", offsetType));
        }

        long offset = 0;
        switch (offsetType) {
            case OFFSET_PRESENT:
                offset = 0;
                break;
            case OFFSET_PAST:
                offset = -30;
                break;
            case OFFSET_FUTURE:
                offset = 30;
                break;

            default:
                offset = 0;
                break;
        }

        long systemTime = System.currentTimeMillis() + offset;
        long message = systemTime - (systemTime % 30);
        message = (long) Math.floor(message / TimeUnit.SECONDS.toMillis(30));

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(
                    String.format("LEAVING method %s (returns: %s)", "getValidMessageBySystemTimestamp", message));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(
                        String.format("LEAVING method %s (returns: %s)", "getValidMessageBySystemTimestamp", "***"));
            }
        }

        return message;
    }

    /**
     * Tests a submitted token against the submitted base32EncodedKey
     * 
     * @param token
     *            the token to test
     * @param base32EncodedKey
     *            the base32 encoded key of the account
     * @return true if the token could be authenticated
     * @throws Exception
     *             when we hit an issue
     */
    public boolean validateToken(int token, byte[] base32EncodedKey) throws Exception {
        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("ENTERING method %s(base32EncodedKey %s)", "validateToken", base32EncodedKey));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("ENTERING method %s(base32EncodedKey %s)", "validateToken", "***"));
            }
        }

        boolean result = false;
        // validate against current timestamp. This should be working in most
        // cases if times are synchronized
        int generatedToken = generateValidToken(getValidMessageBySystemTimestamp(OFFSET_PRESENT), base32EncodedKey);
        if (generatedToken == token) {
            result = true;
        }

        // if this was not successful, the user probably just missed the time
        // window of 30 seconds. Testing a token in the past
        if (result == false) {
            generatedToken = generateValidToken(getValidMessageBySystemTimestamp(OFFSET_PAST), base32EncodedKey);
            if (generatedToken == token) {
                result = true;
            }
        }

        // if the token was still not authenticated, the user might have a phone
        // that is slightly in front of our time
        if (result == false) {
            generatedToken = generateValidToken(getValidMessageBySystemTimestamp(OFFSET_FUTURE), base32EncodedKey);
            if (generatedToken == token) {
                result = true;
            }
        }

        // no matter what, we now return the result;
        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("LEAVING method %s (returns: %s)", "validateToken", result));
        }

        return result;
    }

    /**
     * Tests a submitted token against the submitted base32EncodedKey
     * 
     * @param token
     *            the token to test
     * @param base32EncodedKey
     *            the base32 encoded key of the account
     * @return true if the token could be authenticated
     * @throws Exception
     *             when we hit an issue
     */
    public boolean validateToken(int token, char[] base32EncodedKey) throws Exception {
        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("ENTERING method %s(base32EncodedKey %s)", "validateToken", base32EncodedKey));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("ENTERING method %s(base32EncodedKey %s)", "validateToken", "***"));
            }
        }

        boolean result = false;
        byte[] keyByteArray = charArrayToByteArray(base32EncodedKey);
        result = validateToken(token, keyByteArray);

        // no matter what, we now return the result;
        if (_logger.isLoggable(Level.FINE)) {
            _logger.fine(String.format("LEAVING method %s (returns: %s)", "validateToken", result));
        }

        return result;
    }

    /**
     * Tests a submitted token against the submitted base32EncodedKey
     * 
     * @param token
     *            the token to test
     * @param base32EncodedKey
     *            the base32 encoded key of the account
     * @return true if the token could be authenticated
     * @throws Exception
     *             when we hit an issue
     */
    @Deprecated
    public boolean validateToken(int token, String base32EncodedKey) throws Exception {
        if (_logger.isLoggable(Level.FINEST)) {
            _logger.fine(String.format("ENTERING method %s(base32EncodedKey %s)", "validateToken", base32EncodedKey));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("ENTERING method %s(base32EncodedKey %s)", "validateToken", "***"));
            }
        }

        boolean result = false;
        byte[] keyByteArray = base32EncodedKey.getBytes();
        result = validateToken(token, keyByteArray);

        // no matter what, we now return the result;
        if (_logger.isLoggable(Level.FINE)) {
            _logger.fine(String.format("LEAVING method %s (returns: %s)", "validateToken", result));
        }

        return result;
    }

    /**
     * converts a long to a byteArray.
     * 
     * @param message
     *            the long to convert to a byteArray
     * @return the byteArray according to specification
     */
    private static byte[] longToByteArray(long message) {
        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("ENTERING method %s(message %s)", "longToByteArray", message));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("ENTERING method %s(message %s)", "longToByteArray", "***"));
            }
        }

        // define the array
        byte[] data = new byte[8];
        long value = message;

        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest(String.format("LEAVING method %s (returns: %s)", "validateToken", data));
        } else {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.fine(String.format("LEAVING method %s (returns: %s)", "validateToken", "***"));
            }
        }
        return data;
    }

    /**
     * converts a char array to its byte array representation
     * 
     * @param charArray
     *            the char array to convert
     * @return the converted byte array
     */
    private static byte[] charArrayToByteArray(char[] charArray) {
        byte[] result = new byte[charArray.length];

        for (int i = 0; i < charArray.length; i++) {
            result[i] = (byte) charArray[i];
        }

        return result;
    }

    /**
     * converts a byte array to its char array representation
     * 
     * @param byteArray
     *            the byte array to convert
     * @return the converted char array
     */
    private static char[] byteArrayToCharArray(byte[] byteArray) {
        char[] result = new char[byteArray.length];

        for (int i = 0; i < byteArray.length; i++) {
            result[i] = (char) byteArray[i];
        }

        return result;
    }
}
