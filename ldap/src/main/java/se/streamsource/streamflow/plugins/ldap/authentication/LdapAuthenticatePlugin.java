package se.streamsource.streamflow.plugins.ldap.authentication;

import org.qi4j.api.configuration.Configuration;
import org.qi4j.api.mixin.Mixins;
import org.qi4j.api.service.ServiceComposite;
import se.streamsource.streamflow.server.plugin.authentication.Authenticate;
import se.streamsource.streamflow.server.plugin.authentication.UserValue;

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
      extends ServiceComposite, Authenticate, Configuration
{
   class Mixin implements Authenticate
   {

      public boolean authenticate( UserValue user )
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
            String base = "o=sevenSeas";
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

               System.out.println( "dn: " + dn );
            }

            if (dn == null || enm.hasMore())
            {
               // uid not found or not unique
               throw new NamingException( "Authentication failed" );
            }

            // Step 3: Bind with found DN and given password
            ctx.addToEnvironment( Context.SECURITY_PRINCIPAL, dn );
            ctx.addToEnvironment( Context.SECURITY_CREDENTIALS, password );
            // Perform a lookup in order to force a bind operation with JNDI
            ctx.lookup( dn );
            System.out.println( "Authentication successful" );
            return true;
         } catch (NamingException e)
         {
            System.out.println( e.getMessage() );
         } finally
         {
            try
            {
               ctx.close();
            } catch (NamingException e)
            {
               e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
         }
         return false;
      }
   }
}
