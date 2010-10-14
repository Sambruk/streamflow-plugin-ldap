package se.streamsource.streamflow.plugins.ldap.authentication;

import org.qi4j.api.configuration.Configuration;
import org.qi4j.api.mixin.Mixins;
import org.qi4j.api.service.ServiceComposite;
import org.restlet.data.Status;
import org.restlet.resource.ResourceException;
import se.streamsource.streamflow.server.plugin.authentication.Authenticator;
import se.streamsource.streamflow.server.plugin.authentication.UserIdentityValue;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.Hashtable;


@Mixins(LdapAuthenticatePlugin.Mixin.class)
public interface LdapAuthenticatePlugin
      extends ServiceComposite, Authenticator, Configuration
{


   abstract class Mixin implements LdapAuthenticatePlugin
   {

      public void authenticate( UserIdentityValue user )
      {


         Hashtable env = new Hashtable();
         env.put( Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory" );
         env.put( Context.PROVIDER_URL, "ldap://localhost:10389/" );
         env.put( Context.SECURITY_AUTHENTICATION, "simple" );

         String uid = user.username().get();
         String password = user.password().get();

         DirContext ctx = null;
         try
         {
            // Step 1: Bind anonymously
            ctx = new InitialDirContext( env );

            // Step 2: Search the directory
            String base = "o=streamsource";
            String filter = "(&(objectClass=inetOrgPerson)(uid={0}))";
            SearchControls ctls = new SearchControls();
            ctls.setSearchScope( SearchControls.SUBTREE_SCOPE );
            ctls.setReturningAttributes( new String[0] );
            ctls.setReturningObjFlag( true );
            NamingEnumeration enm = ctx.search( base, filter, new String[]{uid}, ctls );

            String dn = null;
            if (enm.hasMore())
            {
               SearchResult result = (SearchResult) enm.next();
               dn = result.getNameInNamespace();
            }

            if (enm.hasMore())
            {
               // More than one user found
               throw new ResourceException( Status.CLIENT_ERROR_UNAUTHORIZED, Authenticator.error.authentication_username_not_unique.toString() );
            }

            if (dn == null)
            {
               // uid not found
               throw new ResourceException( Status.CLIENT_ERROR_UNAUTHORIZED, Authenticator.error.authentication_bad_username_password.toString() );
            }

            // Step 3: Bind with found DN and given password
            ctx.addToEnvironment( Context.SECURITY_PRINCIPAL, dn );
            ctx.addToEnvironment( Context.SECURITY_CREDENTIALS, password );
            // Perform a lookup in order to force a bind operation with JNDI
            ctx.lookup( dn );
         } catch (NamingException e)
         {
            throw new ResourceException( Status.CLIENT_ERROR_UNAUTHORIZED, Authenticator.error.authentication_bad_username_password.toString() );
         } finally
         {
            try
            {
               ctx.close();
            } catch (NamingException e)
            {
               //ignore
            }
         }
      }


   }
}
