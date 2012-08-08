/**
 *
 * Copyright 2009-2012 Jayway Products AB
 *
 * License statement goes here
 */
package se.streamsource.streamflow.plugins.ldap;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.GetMethod;
import org.junit.Test;
import se.streamsource.streamflow.util.Strings;

import java.io.IOException;

import static org.junit.Assert.*;

//@Ignore
public class LdapPluginTest
{

   @Test
   public void testUserdetails() throws HttpException, IOException
   {
      String result = invokeAndTestUserdetails("henrikreinhold", "henrik", 200);
      assertEquals(
            /*"{\"emailAddress\":\"henrik.reinhold@jayway.com\",\"name\":\"Henrik R\",\"phoneNumber\":\"henrik.reinhold@jayway.com\",\"username\":\"henrikreinhold\"}",*/
            "{\"emailAddress\":\"henrik.reinhold@jayway.com\",\"name\":\"Henrik Reinhold\",\"phoneNumber\":\"\",\"username\":\"henrikreinhold\"}",
            result);
   }

   @Test
   public void testAuthentication() throws HttpException, IOException
   {
      String result = invokeAndTestAuthentication("henrikreinhold", "henrik", 204);
      assertNull(result);
   }

   @Test
   public void testUserNotFound() throws HttpException, IOException
   {
      String result = invokeAndTestUserdetails("userdoesntexist", "wrongpassword", 401);
      assertEquals("The request requires user authentication", result);

      result = invokeAndTestAuthentication("userdoesntexist", "wrongpassword", 401);
      assertEquals("The request requires user authentication", result);
   }

   @Test
   public void testWrongPassword() throws HttpException, IOException
   {
      String result = invokeAndTestUserdetails("henrikreinhold", "wrongpassword", 401);
      assertEquals("The request requires user authentication", result);

      result = invokeAndTestAuthentication("henrikreinhold", "wrongpassword", 401);
      assertEquals("The request requires user authentication", result);
   }

   @Test
   public void testUserExistsButNotMemberOfCorrectGroup() throws IOException
   {
      String result = invokeAndTestUserdetails("miltonhauser", "miltonhauser", 401);
      assertEquals("The request requires user authentication", result);

      result = invokeAndTestAuthentication("miltonhauser", "miltonhauser", 401);
      assertEquals("The request requires user authentication", result);
   }

   @Test
   public void testImportGroups() throws IOException
   {
      String result = invokeAndTestImportGroups( 200 );
      //assertEquals( "", result );
   }

   @Test
   public void testImportUsers() throws IOException
   {
      String result = invokeAndTestImportUsers( 200 );
      //assertEquals( "", result );
   }
   
   private String invokeAndTestUserdetails(String username, String password, int expectedStatus) throws IOException
   {
      return invokeAndTest("http://localhost:8085/ldap/authentication/userdetails", username, password, expectedStatus);
   }

   private String invokeAndTestAuthentication(String username, String password, int expectedStatus) throws IOException
   {
      return invokeAndTest("http://localhost:8085/ldap/authentication", username, password, expectedStatus);
   }


   private String invokeAndTestImportGroups( int expectedStatus ) throws IOException
   {
      return invokeAndTest( "http://localhost:8085/ldap/import/groups", null, null, expectedStatus );
   }

   private String invokeAndTestImportUsers( int expectedStatus ) throws IOException
   {
      return invokeAndTest( "http://localhost:8085/ldap/import/users", null, null, expectedStatus );
   }

   private String invokeAndTest(String url, String username, String password, int expectedStatus) throws IOException
   {
      HttpClient client = new HttpClient();

      GetMethod get = new GetMethod(url);

      if( !Strings.empty( username ))
      {
         client.getState().setCredentials(new AuthScope(null, -1), new UsernamePasswordCredentials(username, password));
         get.setDoAuthentication(true);
      }

      try
      {
         int status = client.executeMethod(get);
         assertEquals(expectedStatus, status);

         return get.getResponseBodyAsString();

      } finally
      {
         get.releaseConnection();
      }
   }


}
