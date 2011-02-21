package se.streamsource.streamflow.plugins.ldap.helper;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.qi4j.api.configuration.Configuration;

import se.streamsource.streamflow.plugins.ldap.authentication.LdapAuthenticatePluginConfiguration;
import se.streamsource.streamflow.plugins.ldap.authentication.LdapAuthenticatePluginConfiguration.Name;
import se.streamsource.streamflow.util.Strings;

public class LdapHelper
{

   private Configuration<LdapAuthenticatePluginConfiguration> config;

   public LdapHelper(Configuration<LdapAuthenticatePluginConfiguration> config)
   {
      this.config = config;

      checkConfig();
   }
   
   public <T> List<T> search(String base, String filter, SearchControls controls, SearchResultMapper<T> mapper)
         throws NamingException
   {
      return search(base, filter, null, controls, mapper);
   }

   public <T> List<T> search(String base, String filter, Object[] filterArgs, SearchControls controls,
         SearchResultMapper<T> mapper) throws NamingException
   {
      List<T> result = new ArrayList<T>();
      DirContext ctx = createInitialContext();

      NamingEnumeration<SearchResult> enm = null;
      try
      {
         enm = ctx.search(base, filter, filterArgs, controls);

         if (enm.hasMore())
         {
            result.add(mapper.mapFromSearchResult(enm.next()));
         }

      } finally
      {
         closeContextAndNamingEnumeration(ctx, enm);
      }
      return result;
   }

   public <T> T lookup(String dn, AttributesMapper<T> mapper) throws NamingException
   {
      DirContext ctx = createInitialContext();
      
      try {
         Attributes attributes = ctx.getAttributes(dn);
         return mapper.mapFromAttribute(attributes);
      
      } finally {
         closeContext(ctx);
      }
   }


   public <T> T lookup(String dn, String uid, String password, AttributesMapper<T> mapper) throws NamingException
   {
      DirContext ctx = createInitialContext();
      ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, dn);
      ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
      
      try {
         Attributes attributes = ctx.getAttributes(dn);
         return mapper.mapFromAttribute(attributes);
      
      } finally {
         closeContext(ctx);
      }
   }
   
   private DirContext createInitialContext() throws NamingException
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

      return new InitialDirContext(env);
   }

   @SuppressWarnings("rawtypes")
   private void closeContextAndNamingEnumeration(DirContext ctx, NamingEnumeration results)
   {

      closeNamingEnumeration(results);
      closeContext(ctx);
   }

   private void closeContext(DirContext ctx)
   {
      if (ctx != null)
      {
         try
         {
            ctx.close();
         } catch (Exception e)
         {
            // Ignore
         }
      }
   }

   @SuppressWarnings("rawtypes")
   private void closeNamingEnumeration(NamingEnumeration namingEnumeration)
   {
      if (namingEnumeration != null)
      {
         try
         {
            namingEnumeration.close();
         } catch (Exception e)
         {
            // Ignore
         }
      }
   }

   private void checkConfig()
   {
      Name name = config.configuration().name().get();
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
