package se.streamsource.streamflow.plugins.ldap.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.IOException;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.GetMethod;
import org.junit.Test;

public class LdapAuthenticatePluginTest
{

   @Test
   public void testUserdetails() throws HttpException, IOException
   {
      String result = invokeAndTestUserdetails("henrikreinhold", "henrik", 200);
      assertEquals(
            "{\"emailAddress\":\"henrik.reinhold@jayway.com\",\"name\":\"Henrik R\",\"phoneNumber\":\"henrik.reinhold@jayway.com\",\"username\":\"henrikreinhold\"}",
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
   public void testUserExistsButNotMemberOfCorrectGroup() throws HttpException, IOException
   {
      String result = invokeAndTestUserdetails("arvidhuss", "henrik", 401);
      assertEquals("The request requires user authentication", result);

      result = invokeAndTestAuthentication("arvidhuss", "henrik", 401);
      assertEquals("The request requires user authentication", result);
   }
   
   private String invokeAndTestUserdetails(String username, String password, int expectedStatus) throws IOException
   {
      return invokeAndTest("http://localhost:8085/ldap/authentication/userdetails", username, password, expectedStatus);
   }

   private String invokeAndTestAuthentication(String username, String password, int expectedStatus) throws IOException
   {
      return invokeAndTest("http://localhost:8085/ldap/authentication", username, password, expectedStatus);
   }

   private String invokeAndTest(String url, String username, String password, int expectedStatus) throws IOException
   {
      HttpClient client = new HttpClient();

      client.getState().setCredentials(new AuthScope(null, -1), new UsernamePasswordCredentials(username, password));
      GetMethod get = new GetMethod(url);

      get.setDoAuthentication(true);

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
