/**
 * 
 */

package de.whisperedshouts.tinymfa;

import java.nio.ByteBuffer;
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
 * @version 1.1.2
 *
 */
public class TinyMfaImplementation {

    // a logger object. Make use of it!
    private static final Logger _logger = Logger.getLogger(TinyMfaImplementation.class.getName());

    // this is the default, static width used in the dynamic truncation
    public static final int DYNAMIC_TRUNCATION_WIDTH = 4;

    // that big is our key to be
    public static final int DEFAULT_SECRET_SIZE = 16;

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
    
    // upon key generation, a byte array is filled with random bytes
    // In order to have enough random bytes available, the random byte array's size
    // is going to be this times the keySize
    public static final int BUFFER_MULTIPLICATOR = 8;

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
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "calculateRFC2104HMAC", 
                new Object[] {data, key});
        
        byte[] result               = null;
        SecretKeySpec signingKey    = new SecretKeySpec(key, HMAC_SHA1_ALGORITHM);
        Mac messageAuthCode         = Mac.getInstance(HMAC_SHA1_ALGORITHM);

        messageAuthCode.init(signingKey);
        result = messageAuthCode.doFinal(data);

        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "calculateRFC2104HMAC", 
                result);
        
        return result;
    }

    /**
     * Generates a new secretKey and encodes it to base32
     * 
     * @return the byte array representation of the base32 encoded secret key
     */
    public static byte[] generateBase32EncodedSecretKeyByteArray() {
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "generateBase32EncodedSecretKeyByteArray");

        byte[] bEncodedKey = generateBase32EncodedSecretKeyByteArray(TinyMfaImplementation.DEFAULT_SECRET_SIZE);

        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "generateBase32EncodedSecretKeyByteArray", 
                "***");

        return bEncodedKey;
    }
    
    /**
     * Generates a new secretKey and encodes it to base32
     * 
     * @param keySize
     *            the size (in bytes) of the key to generate
     * @return the byte array representation of the base32 encoded secret key
     */
    public static byte[] generateBase32EncodedSecretKeyByteArray(int keySize) {
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "generateBase32EncodedSecretKeyByteArray");
        
        // Allocating the buffer
        byte[] buffer = new byte[(keySize * TinyMfaImplementation.BUFFER_MULTIPLICATOR)];

        // Filling the buffer with random numbers.
        new Random().nextBytes(buffer);

        // Getting the key and converting it to Base32
        byte[] secretKey   = Arrays.copyOf(buffer, keySize);
        byte[] bEncodedKey = Base32Util.encode(secretKey);

        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "generateBase32EncodedSecretKeyByteArray", 
                "***");

        return bEncodedKey;
    }

    
    /**
     * Generates a new secretKey and encodes it to base32
     * 
     * @deprecated this returns a String object, that is immutable in java.
     *             Better use either generateBase32EncodedSecretKeyByteArray()
     *             or generateBase32EncodedSecretKeyCharArray
     * @return the base32 encoded secretKey
     */
    @Deprecated
    public static String generateBase32EncodedSecretKey() {
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "generateBase32EncodedSecretKey");

        byte[] bEncodedKey = generateBase32EncodedSecretKeyByteArray();
        String encodedKey  = new String(bEncodedKey);

        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "generateBase32EncodedSecretKey", 
                "***");

        return encodedKey;
    }

    /**
     * Generates a new secretKey and encodes it to base32
     * 
     * @return the base32 encoded secretKey as a char array
     */
    public static char[] generateBase32EncodedSecretKeyCharArray() {
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "generateBase32EncodedSecretKeyCharArray");

        byte[] bEncodedKey = generateBase32EncodedSecretKeyByteArray();
        char[] encodedKey  = byteArrayToCharArray(bEncodedKey);

        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "generateBase32EncodedSecretKeyCharArray", 
                "***");

        return encodedKey;
    }

    /**
     * generates a valid token for a timestamp and a base32 encoded secretKey
     * 
     * @deprecated use the alternatives for char- and byte arrays
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
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "generateValidToken",
                new Object[] {message, "***"});
        
        int token = 0;
        try {

            byte[] keyByteArray = base32SecretKey.getBytes();
            token = generateValidToken(message, keyByteArray);

        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            _logger.severe(e.getMessage());
            throw new Exception(e.getMessage());
        }

        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "generateValidToken", 
                token);

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
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "generateValidToken",
                new Object[] {message, "***"});
        
        int token = 0;
        
        try {
            byte[] byteArray = charArrayToByteArray(base32SecretKey);
            token = generateValidToken(message, byteArray);

        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            _logger.severe(e.getMessage());
            throw new Exception(e.getMessage());
        }

        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "generateValidToken", 
                token);

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
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "generateValidToken",
                new Object[] {message, "***"});

        int token           = 0;
        byte[] keyBytes     = null;
        byte[] messageBytes = null;
        
        // let's process
        try {
            // the key is base32 encoded
            keyBytes = Base32Util.decode(base32SecretKey);
            // get an 8byte array derived from the message
            messageBytes = TinyMfaImplementation.messageToByteArray(message);
            // generate the rfc2104hmac String out of timestamp and key
            byte[] rfc2104hmac = TinyMfaImplementation.calculateRFC2104HMAC(messageBytes, keyBytes);

            // get the decimal representation of the last byte
            // this will be used as a offset. i.E if the last byte was 4 (as
            // decimal), we will derive the dynamic trunacted result, starting at the 4th
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

        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "generateValidToken", 
                token);

        return token;
    }

    /**
     * returns a message based on a "corrected timestamp" This method will get
     * the current system time (Milliseconds since 1970), then remove the
     * seconds elapsed since the last half minute (i.E. 34 becomes 30). Last, we
     * divide this by 30.
     * 
     * @param systemTimestamp
     *            the timestamp to use
     * @return the message
     */
    public static long getValidMessageBySystemTimestamp(long systemTimestamp) {
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "getValidMessageBySystemTimestamp",
                new Object[] {systemTimestamp});

        long message = getValidMessageBySystemTimestamp(systemTimestamp, OFFSET_PRESENT);

        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "getValidMessageBySystemTimestamp", 
                message);

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
     * @param systemTimestamp
     *            the timestamp to use
     * @return the message
     */
    public static long getValidMessageBySystemTimestamp(long systemTimestamp, int offsetType) {
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "getValidMessageBySystemTimestamp",
                new Object[] {systemTimestamp, offsetType});

        long offset = 0;
        switch (offsetType) {
            case OFFSET_PRESENT:    // Do not add an offset
                offset += 0;
                break;
            case OFFSET_FUTURE:     // Add an offset of 30 second into the future
                offset += 30000;
                break;
            case OFFSET_PAST:       // Add an offset of 30 second into the past
                offset -= 30000;
                break;
            default:                // however you landed here - we will add no offset
                offset += 0;
                break;
        }

        long systemTime = systemTimestamp + offset;
        long message    = systemTime - (systemTime % 30);
        message         = (long) Math.floor(message / TimeUnit.SECONDS.toMillis(30));

        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "getValidMessageBySystemTimestamp", 
                message);

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
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "validateToken",
                new Object[] {token, "***"});

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
        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "validateToken", 
                result);

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
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "validateToken",
                new Object[] {token, "***"});

        boolean result      = false;
        byte[] keyByteArray = charArrayToByteArray(base32EncodedKey);
        result              = validateToken(token, keyByteArray);

        // no matter what, we now return the result;
        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "validateToken", 
                result);

        return result;
    }

    /**
     * Tests a submitted token against the submitted base32EncodedKey
     * 
     * @deprecated use the alternatives provided for char- or byte arrays
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
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "validateToken",
                new Object[] {token, "***"});

        boolean result      = false;
        byte[] keyByteArray = base32EncodedKey.getBytes();
        result              = validateToken(token, keyByteArray);

        // no matter what, we now return the result;
        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "validateToken", 
                result);

        return result;
    }

    /**
     * converts a long to a byteArray.
     * 
     * @deprecated deprecated in favor of using the ByteBuffer of the java.nio
     *             package to drastically improve readability check out method
     *             'messageToByteArray(long message)'
     * @param message
     *            the long to convert to a byteArray
     * @return the byteArray according to specification
     */
    @SuppressWarnings("unused")
    @Deprecated
    private static byte[] longToByteArray(long message) {
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "longToByteArray",
                new Object[] {message});

        // define the array
        byte[] data = new byte[8];
        long value  = message;

        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "longToByteArray", 
                data);
        
        return data;
    }
    
    /**
     * converts a long to a byteArray.
     * 
     * @param message
     *            the long to convert to a byteArray
     * @return the byteArray according to specification
     */
    private static byte[] messageToByteArray(long message) {
        _logger.entering(TinyMfaImplementation.class.getName(), 
                "messageToByteArray",
                new Object[] {message});
        
        // allocate a ByteBuffer. a Long in java is 8 bytes
        ByteBuffer byteBuffer = ByteBuffer.allocate(8);
        byte[]     data       = byteBuffer.putLong(message).array();
        
        _logger.exiting(TinyMfaImplementation.class.getName(), 
                "messageToByteArray", 
                data);
        
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
        _logger.entering(TinyMfaImplementation.class.getName(), "charArrayToByteArray");
        byte[] result = new byte[charArray.length];

        for (int i = 0; i < charArray.length; i++) {
            result[i] = (byte) charArray[i];
        }

        _logger.exiting(TinyMfaImplementation.class.getName(), "charArrayToByteArray");
        
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
        _logger.entering(TinyMfaImplementation.class.getName(), "byteArrayToCharArray");
        
        char[] result = new char[byteArray.length];

        for (int i = 0; i < byteArray.length; i++) {
            result[i] = (char) byteArray[i];
        }

        _logger.exiting(TinyMfaImplementation.class.getName(), "byteArrayToCharArray");
        
        return result;
    }
}
