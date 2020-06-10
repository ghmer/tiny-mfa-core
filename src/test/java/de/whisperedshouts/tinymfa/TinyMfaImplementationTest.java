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

    public static final String TESTKEY = "NOU4XWWCB4ZJOPNZRF6WRTFRMQ======";
    public static final long   MESSAGE = 53060604;
    public static final long   TOTP    = 208443;

    /**
     * Test method for {@link de.whisperedshouts.tinymfa.TinyMfaImplementation#generateBase32EncodedSecretKey()}.
     */
    @Test
    public void testGenerateBase32EncodedSecretKey() {
        assertNotNull(TinyMfaImplementation.generateBase32EncodedSecretKey());
    }

    /**
     * Test method for {@link de.whisperedshouts.tinymfa.TinyMfaImplementation#generateValidToken(java.lang.Long, java.lang.String)}.
     */
    @Test
    public void testGenerateValidToken() {
        int token;
        try {
            token = TinyMfaImplementation.generateValidToken(MESSAGE, TESTKEY);
            assertNotEquals(token, 0);
            assertEquals(token, TOTP);
        } catch (Exception e) {
            fail(e.getMessage());
        }
        
    }

    /**
     * Test method for {@link de.whisperedshouts.tinymfa.TinyMfaImplementation#getValidMessageBySystemTimestamp()}.
     */
    @Test
    public void testGetValidMessageBySystemTimestamp() {
        assertNotNull(TinyMfaImplementation.getValidMessageBySystemTimestamp());
    }

}
