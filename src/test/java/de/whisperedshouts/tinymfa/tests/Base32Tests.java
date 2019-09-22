/**
 * 
 */
package de.whisperedshouts.tinymfa.tests;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.apache.commons.codec.binary.Base32;
import org.junit.Before;
import org.junit.Test;

import de.whisperedshouts.tinymfa.TinyMfaImplementation;
import de.whisperedshouts.util.Base32Util;

/**
 * @author mario.ragucci
 *
 */
public class Base32Tests {

  public List<byte[]> secretList = new ArrayList<>();
  public List<String> decrypt = new ArrayList<>();
  /**
   * @throws java.lang.Exception
   */
  @Before
  public void setUp() throws Exception {
    
    for(int i = 0; i < 99999; i++) {
      byte[] buffer = new byte[128];
      new Random().nextBytes(buffer);
      byte[] secretKey    = Arrays.copyOf(buffer, TinyMfaImplementation.FINAL_SECRET_SIZE);
      secretList.add(secretKey);
    }
    
    for(byte[] array : secretList) {
      decrypt.add(new Base32().encodeToString(array));
    }
  }

  /**
   * Test method for {@link de.whisperedshouts.util.Base32Util#decode(byte[])}.
   */
  @Test
  public void testDecodeByteArray() {
    for(String s : decrypt) {
      byte[] a = Base32Util.decode(s.getBytes());
      byte[] b = new Base32().decode(s);
      assertArrayEquals(b, a);
    }
  }

  /**
   * Test method for {@link de.whisperedshouts.util.Base32Util#decode(byte[], java.lang.String)}.
   */
  @Test
  public void testDecodeByteArrayString() {
    for(String s : decrypt) {
      byte[] a = Base32Util.decode(s.getBytes(), Base32Util.BASE32_CHARSET);
      byte[] b = new Base32().decode(s);
      assertArrayEquals(b, a);
    }
  }

  /**
   * Test method for {@link de.whisperedshouts.util.Base32Util#decode(java.lang.String)}.
   */
  @Test
  public void testDecodeString() {
    for(String s : decrypt) {
      byte[] a = Base32Util.decode(s);
      byte[] b = new Base32().decode(s);
      assertArrayEquals(b, a);
    }
  }

  /**
   * Test method for {@link de.whisperedshouts.util.Base32Util#decode(java.lang.String, java.lang.String)}.
   */
  @Test
  public void testDecodeStringString() {
    for(String s : decrypt) {
      byte[] a = Base32Util.decode(s, Base32Util.BASE32_CHARSET);
      byte[] b = new Base32().decode(s);
      assertArrayEquals(b, a);
    }
  }

  /**
   * Test method for {@link de.whisperedshouts.util.Base32Util#encode(byte[])}.
   */
  @Test
  public void testEncodeByteArray() {
    for(byte[] array : secretList) {
      byte[] a = Base32Util.encode(array);
      byte[] b = new Base32().encode(array);
      assertArrayEquals(b, a);
    }
  }

  /**
   * Test method for {@link de.whisperedshouts.util.Base32Util#encode(byte[], java.lang.String)}.
   */
  @Test
  public void testEncodeByteArrayString() {
    for(byte[] array : secretList) {
      byte[] a = Base32Util.encode(array, Base32Util.BASE32_CHARSET);
      byte[] b = new Base32().encode(array);
      assertArrayEquals(b, a);
    }
    
    
  }

  /**
   * Test method for {@link de.whisperedshouts.util.Base32Util#encodeToString(byte[])}.
   */
  @Test
  public void testEncodeToStringByteArray() {
    for(byte[] array : secretList) {
      String a = Base32Util.encodeToString(array);
      String b = new Base32().encodeToString(array);
      assertEquals(b, a);
    }
  }

  /**
   * Test method for {@link de.whisperedshouts.util.Base32Util#encodeToString(byte[], java.lang.String)}.
   */
  @Test
  public void testEncodeToStringByteArrayString() {
    for(byte[] array : secretList) {
      String a = Base32Util.encodeToString(array);
      String b = new Base32().encodeToString(array);
      assertEquals(b, a);
    }
  }

}
