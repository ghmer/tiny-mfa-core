/**
 * 
 */
package de.whisperedshouts.tinymfa;

import static org.junit.Assert.*;

import org.junit.Test;


/**
 * @author mario
 *
 */
public class TinyMfaImplementationTest {

    public static final String TESTKEY          = "NOU4XWWCB4ZJOPNZRF6WRTFRMQ======";
    public static final long   TOTP             = 935619L;
    public static final long   MESSAGE_PAST     = 53082851L;
    public static final long   MESSAGE_PRESENT  = 53082852L;
    public static final long   MESSAGE_FUTURE   = 53082853L;
    public static final long   TIMESTAMP        = 1592485571800L;

    @SuppressWarnings("deprecation")
    @Test
    public void testGenerateBase32EncodedSecretKey() {
        assertNotNull(TinyMfaImplementation.generateBase32EncodedSecretKey());
    }

    @SuppressWarnings("deprecation")
    @Test
    public void testGenerateValidToken() {
        int token;
        try {
            token = TinyMfaImplementation.generateValidToken(MESSAGE_PRESENT, TESTKEY);
            assertNotEquals(token, 0);
            assertEquals(token, TOTP);
        } catch (Exception e) {
            fail(e.getMessage());
        }
        
    }
    
    @Test
    public void testGenerateValidTokenWithCharArray() {
        int token;
        try {
            token = TinyMfaImplementation.generateValidToken(MESSAGE_PRESENT, TESTKEY.toCharArray());
            assertNotEquals(token, 0);
            assertEquals(token, TOTP);
        } catch (Exception e) {
            fail(e.getMessage());
        }
        
    }
    
    @Test
    public void testGenerateValidTokenWithByteArray() {
        int token;
        try {
            token = TinyMfaImplementation.generateValidToken(MESSAGE_PRESENT, TESTKEY.getBytes());
            assertNotEquals(token, 0);
            assertEquals(token, TOTP);
        } catch (Exception e) {
            fail(e.getMessage());
        }
        
    }

    @Test
    public void testGetValidMessageBySystemTimestamp() {
        long message = TinyMfaImplementation.getValidMessageBySystemTimestamp(TIMESTAMP);
        assertNotNull(message);
        assertEquals(MESSAGE_PRESENT, message);
    }
    
    @Test
    public void testGetValidFutureMessageBySystemTimestamp() {
        long message = TinyMfaImplementation.getValidMessageBySystemTimestamp(TIMESTAMP, TinyMfaImplementation.OFFSET_FUTURE);
        assertNotNull(message);
        assertEquals(MESSAGE_FUTURE, message);
    }
    
    @Test
    public void testGetValidPastMessageBySystemTimestamp() {
        long message = TinyMfaImplementation.getValidMessageBySystemTimestamp(TIMESTAMP, TinyMfaImplementation.OFFSET_PAST);
        assertNotNull(message);
        assertEquals(MESSAGE_PAST, message);
    }
}
