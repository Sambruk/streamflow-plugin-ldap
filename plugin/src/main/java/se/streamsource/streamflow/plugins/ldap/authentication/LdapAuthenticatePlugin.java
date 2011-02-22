/**
 *
 * Copyright 2010 Streamsource AB
 *
 * License statement goes here
 */

package se.streamsource.streamflow.plugins.ldap.authentication;

import java.util.ArrayList;
import java.util.List;

import javax.naming.AuthenticationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.qi4j.api.configuration.Configuration;
import org.qi4j.api.injection.scope.Structure;
import org.qi4j.api.injection.scope.This;
import org.qi4j.api.mixin.Mixins;
import org.qi4j.api.service.Activatable;
import org.qi4j.api.service.ServiceComposite;
import org.qi4j.api.value.ValueBuilder;
import org.qi4j.api.value.ValueBuilderFactory;
import org.restlet.data.Status;
import org.restlet.resource.ResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.streamsource.streamflow.plugins.ldap.helper.AttributesMapper;
import se.streamsource.streamflow.plugins.ldap.helper.LdapHelper;
import se.streamsource.streamflow.plugins.ldap.helper.SearchResultMapper;
import se.streamsource.streamflow.server.plugin.authentication.Authenticator;
import se.streamsource.streamflow.server.plugin.authentication.GroupValue;
import se.streamsource.streamflow.server.plugin.authentication.UserDetailsList;
import se.streamsource.streamflow.server.plugin.authentication.UserDetailsValue;
import se.streamsource.streamflow.server.plugin.authentication.UserIdentityValue;
import se.streamsource.streamflow.server.plugin.synchronization.UserSynchronizer;

@Mixins(LdapAuthenticatePlugin.Mixin.class)
public interface LdapAuthenticatePlugin extends ServiceComposite, Authenticator, UserSynchronizer, Activatable,
      Configuration
{

   abstract class Mixin implements LdapAuthenticatePlugin
   {

      private static final Logger logger = LoggerFactory.getLogger(LdapAuthenticatePlugin.class);

      private static final String AUTHORIZED_USERS_GROUP = "streamflow";

      @Structure
      ValueBuilderFactory vbf;

      @This
      Configuration<LdapAuthenticatePluginConfiguration> config;

      LdapHelper ldapHelper;

      public void passivate() throws Exception
      {
      }

      public void activate() throws Exception
      {
         if (LdapAuthenticatePluginConfiguration.Name.not_configured != config.configuration().name().get())
            ldapHelper = new LdapHelper(config);
      }

      public UserDetailsList allUsersInGroup(GroupValue groupValue)
      {
         String filter = "(&(uniqueMember=*)(objectClass=groupOfUniqueNames))";

         SearchControls controls = new SearchControls();
         controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
         controls.setReturningAttributes(new String[]
         { "uniqueMember" });
         controls.setReturningObjFlag(true);

         try
         {
            String groupDn = "cn=" + groupValue.name().get() + "," + config.configuration().groupSearchbase().get();
            List<List<String>> names = ldapHelper.search(groupDn, filter, controls,
                  new SearchResultMapper<List<String>>()
                  {
                     public List<String> mapFromSearchResult(SearchResult result) throws NamingException
                     {
                        List<String> listNames = new ArrayList<String>();

                        @SuppressWarnings("unchecked")
                        NamingEnumeration<String> allNames = (NamingEnumeration<String>) result.getAttributes()
                              .get("uniqueMember").getAll();

                        while (allNames.hasMore())
                        {
                           listNames.add(allNames.next());
                        }
                        return listNames;
                     }
                  });

            UserDetailsList resultList = vbf.newValue(UserDetailsList.class);

            for (String dn : names.get(0))
            {
               resultList.users().get().add(ldapHelper.lookup(dn, new UserDetailsValueAttributesMapper()));
            }

            return resultList;

         } catch (NameNotFoundException nnfe)
         {
            logger.error("Could not found a group with that name in directory", nnfe);
            throw new ResourceException(Status.CLIENT_ERROR_NOT_FOUND);
         } catch (NamingException ne)
         {
            logger.error("Couldn't read users from LDAP group", ne);
            throw new ResourceException(Status.SERVER_ERROR_INTERNAL, ne);
         }
      }

      public void authenticate(UserIdentityValue user)
      {
         userdetails(user);
      }

      public UserDetailsValue userdetails(UserIdentityValue user)
      {
         try
         {
            String username = user.username().get();
            String password = user.password().get();

            String filter = createFilterForUidQuery();

            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningObjFlag(true);

            List<String> names = ldapHelper.search(config.configuration().userSearchbase().get(), filter, new String[]
            { username }, controls, new SearchResultMapper<String>()
            {
               public String mapFromSearchResult(SearchResult result) throws NamingException
               {
                  return result.getNameInNamespace();
               }
            });

            if (names.isEmpty() || names.size() > 1)
            {
               throw new ResourceException(Status.CLIENT_ERROR_UNAUTHORIZED);
            }

            String dn = names.get(0);
            validateGroupMembership(dn);

            // Perform a lookup in order to force a bind operation with JNDI
            UserDetailsValue userDetails = ldapHelper.lookup(dn, username, password,
                  new UserDetailsValueAttributesMapper());

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

      private void validateGroupMembership(String dn) throws NamingException
      {
         SearchControls groupCtls = new SearchControls();
         groupCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

         String[] returningAttributes = null;
         String filter = null;
         switch (config.configuration().name().get())
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

         String groupDn = "cn=" + AUTHORIZED_USERS_GROUP + "," + config.configuration().groupSearchbase().get();
         List<String> groupNames = ldapHelper.search(groupDn, filter, new String[]
         { dn }, groupCtls, new SearchResultMapper<String>()
         {

            public String mapFromSearchResult(SearchResult result)
            {
               return result.getNameInNamespace();
            }
         });

         if (groupNames.isEmpty())
         {
            throw new ResourceException(Status.CLIENT_ERROR_UNAUTHORIZED);
         }
      }

      private String createFilterForUidQuery()
      {
         switch (config.configuration().name().get())
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

      private final class UserDetailsValueAttributesMapper implements AttributesMapper<UserDetailsValue>
      {
         public UserDetailsValue mapFromAttribute(Attributes attributes) throws NamingException
         {
            ValueBuilder<UserDetailsValue> builder = vbf.newValueBuilder(UserDetailsValue.class);

            Attribute nameAttribute = attributes.get(config.configuration().nameAttribute().get());
            Attribute emailAttribute = attributes.get(config.configuration().emailAttribute().get());
            Attribute phoneAttribute = attributes.get(config.configuration().phoneAttribute().get());

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

            builder.prototype().username().set((String) attributes.get("uid").get());

            return builder.newInstance();
         }
      }
   }
}
