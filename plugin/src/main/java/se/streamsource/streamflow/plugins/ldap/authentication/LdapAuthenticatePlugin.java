/**
 *
 * Copyright 2010 Streamsource AB
 *
 * License statement goes here
 */

package se.streamsource.streamflow.plugins.ldap.authentication;

import org.qi4j.api.configuration.Configuration;
import org.qi4j.api.injection.scope.Structure;
import org.qi4j.api.injection.scope.This;
import org.qi4j.api.mixin.Mixins;
import org.qi4j.api.service.Activatable;
import org.qi4j.api.service.ServiceComposite;
import org.qi4j.api.structure.Module;
import org.qi4j.api.value.ValueBuilder;
import org.restlet.data.Status;
import org.restlet.resource.ResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.streamsource.streamflow.plugins.ldap.authentication.LdapAuthenticatePluginConfiguration.Name;
import se.streamsource.streamflow.server.plugin.authentication.Authenticator;
import se.streamsource.streamflow.server.plugin.authentication.UserDetailsValue;
import se.streamsource.streamflow.server.plugin.authentication.UserIdentityValue;
import se.streamsource.streamflow.util.Strings;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.Hashtable;

@Mixins(LdapAuthenticatePlugin.Mixin.class)
public interface LdapAuthenticatePlugin extends ServiceComposite, Authenticator, Activatable,
      Configuration
{

   abstract class Mixin implements LdapAuthenticatePlugin
   {

      private static final Logger logger = LoggerFactory.getLogger(LdapAuthenticatePlugin.class);

      @Structure
      Module module;

      @This
      Configuration<LdapAuthenticatePluginConfiguration> config;

      public void passivate() throws Exception
      {
      }

      public void activate() throws Exception
      {
         if ( !LdapAuthenticatePluginConfiguration.Name.not_configured.name().equals(  config.configuration().name().get() ) )
            checkConfig();
      }

      public void authenticate(UserIdentityValue user)
      {
         userdetails(user);
      }

      public UserDetailsValue userdetails(UserIdentityValue user)
      {
         checkConfig();

         String uid = user.username().get();
         String password = user.password().get();

         DirContext ctx = null;
         try
         {
            ctx = createInitialContext();

            return lookupUserDetails(ctx, uid, password);

         } finally
         {
            try
            {
               if (ctx != null)
                  ctx.close();
            } catch (NamingException e)
            {
               logger.debug("Error closing context:", e);
            }
         }

      }

      private UserDetailsValue lookupUserDetails(DirContext ctx, String uid, String password)
      {
         try
         {

            String filter = createFilterForUidQuery();

            SearchControls ctls = new SearchControls();
            ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            ctls.setReturningAttributes(new String[]
            { config.configuration().nameAttribute().get(), config.configuration().emailAttribute().get(),
                  config.configuration().phoneAttribute().get() });
            ctls.setReturningObjFlag(true);

            NamingEnumeration<SearchResult> enm = ctx.search(config.configuration().userSearchbase().get(), filter,
                  new String[]
                  { uid }, ctls);

            UserDetailsValue userDetails = null;
            String dn = null;

            if (enm.hasMore())
            {
               SearchResult result = (SearchResult) enm.next();
               dn = result.getNameInNamespace();
               userDetails = createUserDetails(result, uid);
            }

            if (dn == null || enm.hasMore())
            {
               throw new ResourceException(Status.CLIENT_ERROR_UNAUTHORIZED);
            }

            validateGroupMembership(ctx, dn);
            
            ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, dn);
            ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
            // Perform a lookup in order to force a bind operation with JNDI
            ctx.lookup(dn);

            logger.debug("Authentication successful for user: " + dn);

            return userDetails;

         } catch (AuthenticationException ae)
         {
            logger.debug("User could not be authenticated:", ae);
            throw new ResourceException(Status.CLIENT_ERROR_UNAUTHORIZED, ae);

         } catch (NamingException e)
         {
            logger.debug("Unknown error while authenticating user: ", e);
            throw new ResourceException(Status.SERVER_ERROR_INTERNAL, e);
         }
      }

      private void validateGroupMembership(DirContext ctx, String dn) throws NamingException
      {
         SearchControls groupCtls = new SearchControls();
         groupCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

         String[] returningAttributes = null;
         String filter = null;
         switch (LdapAuthenticatePluginConfiguration.Name.valueOf( config.configuration().name().get() ) )
         {
         case ad:
            returningAttributes = new String[]
            { "member" };
            filter = "(&(member={0})(objectClass=groupOfNames))";
            break;
         case edirectory:
            returningAttributes = new String[]
            { "member" };
            filter = "(&(member={0})(objectClass=groupOfNames))";
            break;
         case apacheds:
            returningAttributes = new String[]
            { "uniqueMember" };
            filter = "(&(uniqueMember={0})(objectClass=groupOfUniqueNames))";
            break;
         }

         groupCtls.setReturningAttributes(returningAttributes);
         groupCtls.setReturningObjFlag(true);
         NamingEnumeration<SearchResult> groups = ctx.search(config.configuration().groupSearchbase().get(), filter,
               new String[]
               { dn }, groupCtls);
         if (!groups.hasMore())
         {
            throw new ResourceException(Status.CLIENT_ERROR_UNAUTHORIZED);
         }
      }

      private UserDetailsValue createUserDetails(SearchResult result, String username) throws NamingException
      {
         ValueBuilder<UserDetailsValue> builder = module.valueBuilderFactory().newValueBuilder(UserDetailsValue.class);

         Attribute nameAttribute = result.getAttributes().get(config.configuration().nameAttribute().get());
         Attribute emailAttribute = result.getAttributes().get(config.configuration().emailAttribute().get());
         Attribute phoneAttribute = result.getAttributes().get(config.configuration().phoneAttribute().get());

         if (nameAttribute != null)
         {
            builder.prototype().name().set((String) nameAttribute.get());
         }

         if (emailAttribute != null)
         {
            builder.prototype().emailAddress().set((String) emailAttribute.get());
         }

         if (phoneAttribute != null)
         {
            builder.prototype().phoneNumber().set((String) phoneAttribute.get());
         }
         
         builder.prototype().username().set(username);
         
         return builder.newInstance();
      }

      private String createFilterForUidQuery()
      {
         switch (LdapAuthenticatePluginConfiguration.Name.valueOf( config.configuration().name().get() ) )
         {
         case ad:
            return "(&(objectclass=person)(uid={0}))";
         case edirectory:
            return "(&(objectClass=inetOrgPerson)(uid={0}))";
         case apacheds:
            return "(&(objectClass=inetOrgPerson)(uid={0}))";
         default:
            return null;
         }
      }

      private DirContext createInitialContext()
      {
         Hashtable<String, String> env = new Hashtable<String, String>();
         env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
         env.put(Context.PROVIDER_URL, config.configuration().url().get());
         env.put(Context.SECURITY_AUTHENTICATION, "simple");
         if (!config.configuration().username().get().isEmpty())
         {
            env.put(Context.SECURITY_PRINCIPAL, config.configuration().username().get());
            env.put(Context.SECURITY_CREDENTIALS, config.configuration().password().get());
         }

         DirContext newContext = null;
         try
         {
            newContext = new InitialDirContext(env);

         } catch (AuthenticationException ae)
         {
            logger.warn("Could not log on ldap-server with service account");
            throw new ResourceException(Status.SERVER_ERROR_INTERNAL, ae);
         } catch (NamingException e)
         {
            logger.warn("Problem establishing connection with ldap-server", e);
            throw new ResourceException(Status.SERVER_ERROR_INTERNAL, e);
         }
         return newContext;
      }

      private void checkConfig()
      {
         Name name = LdapAuthenticatePluginConfiguration.Name.valueOf( config.configuration().name().get() );
         if ((LdapAuthenticatePluginConfiguration.Name.ad != name
               && LdapAuthenticatePluginConfiguration.Name.edirectory != name && LdapAuthenticatePluginConfiguration.Name.apacheds != name)
               || Strings.empty(config.configuration().nameAttribute().get())
               || Strings.empty(config.configuration().phoneAttribute().get())
               || Strings.empty(config.configuration().emailAttribute().get())
               || Strings.empty(config.configuration().userSearchbase().get())
               || Strings.empty(config.configuration().groupSearchbase().get()))
         {
            throw new IllegalStateException("Correct configuration is missing");
         }
      }
   }
}
