/**
 *
 * Copyright 2009-2012 Jayway Products AB
 *
 * License statement goes here
 */
package se.streamsource.streamflow.plugins.ldap;

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
import se.streamsource.streamflow.server.plugin.authentication.Authenticator;
import se.streamsource.streamflow.server.plugin.authentication.UserDetailsValue;
import se.streamsource.streamflow.server.plugin.authentication.UserIdentityValue;
import se.streamsource.streamflow.server.plugin.ldapimport.GroupDetailsValue;
import se.streamsource.streamflow.server.plugin.ldapimport.GroupListValue;
import se.streamsource.streamflow.server.plugin.ldapimport.LdapImporter;
import se.streamsource.streamflow.server.plugin.ldapimport.UserListValue;
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
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: arvidhuss
 * Date: 8/6/12
 * Time: 7:44 AM
 * To change this template use File | Settings | File Templates.
 */
@Mixins(LdapPlugin.Mixin.class)
public interface LdapPlugin extends ServiceComposite, Activatable, Authenticator, LdapImporter,
      Configuration
{

   abstract class Mixin implements LdapPlugin
   {
      protected static final Logger logger = LoggerFactory.getLogger( LdapPlugin.class );

      @Structure
      protected Module module;

      @This
      protected Configuration<LdapPluginConfiguration> config;

      protected DirContext ctx;

      public void passivate() throws Exception
      {
         if( ctx != null )
         {
            ctx.close();
            ctx = null;
         }
      }

      public void activate() throws Exception
      {
         if ( !LdapPluginConfiguration.Vendor.not_configured.name()
               .equals(  config.configuration().vendor().get() ) && checkConfigOk() )
         {
            createInitialContext();
         }
      }

      private void createInitialContext()
      {
         Hashtable<String, String> env = new Hashtable<String, String>();
         env.put( Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
         env.put(Context.PROVIDER_URL, config.configuration().url().get());
         env.put(Context.SECURITY_AUTHENTICATION, "simple");

         if (!config.configuration().username().get().isEmpty())
         {
            env.put( Context.SECURITY_PRINCIPAL, config.configuration().username().get());
            env.put(Context.SECURITY_CREDENTIALS, config.configuration().password().get());
         }

         try
         {
            ctx = new InitialDirContext(env);

            logger.info( "Established connection with LDAP server at " + config.configuration().url().get() );

         } catch (AuthenticationException ae)
         {
            logger.warn("Could not log on ldap-server with service account");
            throw new ResourceException( Status.SERVER_ERROR_INTERNAL, ae);
         } catch (NamingException e)
         {
            logger.warn("Problem establishing connection with ldap-server", e);
            throw new ResourceException(Status.SERVER_ERROR_INTERNAL, e);
         }
      }

      private void resetSecurityCredentials()
            throws NamingException
      {
         ctx.removeFromEnvironment( Context.SECURITY_PRINCIPAL );
         ctx.removeFromEnvironment( Context.SECURITY_CREDENTIALS );
         if(!config.configuration().username().get().isEmpty() )
         {
            ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, config.configuration().username().get());
            ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, config.configuration().password().get());
         }
      }

      protected boolean checkConfigOk()
      {
         LdapPluginConfiguration.Vendor vendor = LdapPluginConfiguration.Vendor.valueOf( config.configuration().vendor().get() );
         if ((LdapPluginConfiguration.Vendor.ad != vendor
               && LdapPluginConfiguration.Vendor.edirectory != vendor && LdapPluginConfiguration.Vendor.apacheds != vendor)
               || Strings.empty( config.configuration().nameAttribute().get() )
               || Strings.empty(config.configuration().phoneAttribute().get())
               || Strings.empty(config.configuration().emailAttribute().get())
               || Strings.empty(config.configuration().userSearchbase().get())
               || Strings.empty(config.configuration().groupSearchbase().get())
               || Strings.empty(config.configuration().streamflowGroupCn().get())
               || Strings.empty(config.configuration().streamflowGroupDn().get()))
         {
            return false;
         }
         return true;
      }

      protected String createFilterForUidQuery()
      {
         switch (LdapPluginConfiguration.Vendor.valueOf( config.configuration().vendor().get() ) )
         {
            case ad:
               return "(&(objectclass=person)(uid={0}))";
            case edirectory:
            case apacheds:
               return "(&(objectClass=inetOrgPerson)(uid={0}))";
            default:
               return null;
         }
      }

      protected String createFilterForFetchUserWithDn()
      {
         switch (LdapPluginConfiguration.Vendor.valueOf( config.configuration().vendor().get() ) )
         {
            case ad:
               return "(objectclass=person)";
            case edirectory:
            case apacheds:
               return "(objectClass=inetOrgPerson)";
            default:
               return null;
         }
      }

      protected String createFilterForFetchGroupWithDn()
      {
         switch (LdapPluginConfiguration.Vendor.valueOf( config.configuration().vendor().get() ) )
         {
            case ad:
               return "(objectclass=groupOfNames)";
            case edirectory:
               return "(objectClass=groupOfNames)";
            case apacheds:
               return "(objectClass=groupOfUniqueNames)";
            default:
               return null;
         }
      }

      protected String memberAttribute()
      {
         switch (LdapPluginConfiguration.Vendor.valueOf( config.configuration().vendor().get() ) )
         {
            case ad:
            case edirectory:
               return "member";
            case apacheds:
               return "uniqueMember";
            default:
               return null;
         }
      }


      String uidAttribute()
      {
         switch (LdapPluginConfiguration.Vendor.valueOf( config.configuration().vendor().get() ) )
         {
            case ad:
            case edirectory:
            case apacheds:
               return "uid";
            default:
               return null;
         }
      }

      String entryUUIDAttribute()
      {
         switch (LdapPluginConfiguration.Vendor.valueOf( config.configuration().vendor().get() ) )
         {
            case ad:
            case edirectory:
            case apacheds:
               return "entryUUID";
            default:
               return null;
         }
      }

      protected String createFilterForGroupsQuery()
      {
         switch (LdapPluginConfiguration.Vendor.valueOf( config.configuration().vendor().get() ) )
         {
            case ad:
            case edirectory:
               return "(&(objectClass=groupOfNames)(!(cn={0})))";
            case apacheds:
               return "(&(objectClass=groupOfUniqueNames)(!(cn={0})))";
            default:
               return null;
         }
      }

      protected String createFilterForMemberOfGroupQuery()
      {
         switch (LdapPluginConfiguration.Vendor.valueOf( config.configuration().vendor().get() ) )
         {
            case ad:
            case edirectory:
               return "(&(member={0})(objectClass=groupOfNames))";
            case apacheds:
               return "(&(uniqueMember={0})(objectClass=groupOfUniqueNames))";
            default:
               return null;
         }
      }

      protected String[] createReturnAttributesForGroupQuery()
      {
         switch (LdapPluginConfiguration.Vendor.valueOf( config.configuration().vendor().get() ) )
         {
            case ad:
            case edirectory:
               return new String[] { memberAttribute() };
            case apacheds:
               return new String[] { config.configuration().nameAttribute().get(),
                     memberAttribute(), entryUUIDAttribute() };
            default:
               return new String[0];
         }
      }

      protected String[] createReturnAttributesForUidQuery()
      {
         return new String[]
               {uidAttribute(),
                     config.configuration().nameAttribute().get(),
                     config.configuration().emailAttribute().get(),
                     config.configuration().phoneAttribute().get() };
      }

      public void authenticate(UserIdentityValue user)
      {
         userdetails(user);
      }

      public UserDetailsValue userdetails(UserIdentityValue user)
      {
         String uid = user.username().get();
         String password = user.password().get();

         if( checkConfigOk() )
         {
            return lookupUserDetails( uid, password);
         } else
         {
            logger.error("Plugin is not reasonably configured!");
            throw new ResourceException(Status.CLIENT_ERROR_PRECONDITION_FAILED);
         }
      }

      private UserDetailsValue lookupUserDetails( String uid, String password)
      {
         try
         {
            resetSecurityCredentials();

            String filter = createFilterForUidQuery();

            SearchControls ctls = new SearchControls();
            ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            ctls.setReturningAttributes( createReturnAttributesForUidQuery() );
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

         String[] returningAttributes = createReturnAttributesForGroupQuery();
         String filter = createFilterForMemberOfGroupQuery();

         groupCtls.setReturningAttributes(returningAttributes);
         groupCtls.setReturningObjFlag(true);
         NamingEnumeration<SearchResult> groups = ctx.search(config.configuration().streamflowGroupDn().get(), filter,
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
         Attribute uid  = result.getAttributes().get( uidAttribute() );

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

         if( uid != null )
         {
            builder.prototype().username().set((String)uid.get() );
         } else
         {
            builder.prototype().username().set( username );
         }

         return builder.newInstance();
      }

      public GroupListValue groups()
      {
         ValueBuilder<GroupListValue> listBuilder = module.valueBuilderFactory().newValueBuilder( GroupListValue.class );
         try
         {
            resetSecurityCredentials();

            SearchControls groupCtls = new SearchControls();
            groupCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            String[] returningAttributes = createReturnAttributesForGroupQuery();
            String filter = createFilterForGroupsQuery();

            groupCtls.setReturningAttributes(returningAttributes);
            groupCtls.setReturningObjFlag(true);
            NamingEnumeration<SearchResult> groups = ctx.search(config.configuration().groupSearchbase().get(), filter,
                  new String[]{ config.configuration().streamflowGroupCn().get() }, groupCtls);

            List<GroupDetailsValue> groupsList = new ArrayList<GroupDetailsValue>( );
            ValueBuilder<GroupDetailsValue> groupBuilder = module.valueBuilderFactory().newValueBuilder( GroupDetailsValue.class );
            while( groups.hasMore() )
            {
               SearchResult searchResult = groups.next();

               Attribute id = searchResult.getAttributes().get( entryUUIDAttribute() );
               groupBuilder.prototype().id().set( (String)id.get() );

               Attribute name = searchResult.getAttributes().get( config.configuration().nameAttribute().get() );
               groupBuilder.prototype().name().set( (String)name.get() );

               List<String> memberIds = new ArrayList<String>(  );
               Attribute members = searchResult.getAttributes().get( memberAttribute() );
               for( int i=0; i<members.size(); i++ )
               {
                  LdapName ldapName = new LdapName( (String)members.get( i ) );
                  for(Rdn rdn : ldapName.getRdns() )
                  {
                     if(uidAttribute().equals( rdn.getType() ))
                        memberIds.add(  (String)rdn.getValue() );
                  }

               }

               groupBuilder.prototype().members().set( memberIds );
               groupsList.add( groupBuilder.newInstance() );
            }

            listBuilder.prototype().groups().set( groupsList );

         } catch (NamingException ne )
         {
            logger.debug("Unknown error while importing groups: ", ne);
            throw new ResourceException(Status.SERVER_ERROR_INTERNAL, ne);
         }

         return listBuilder.newInstance();
      }

      public UserListValue users()
      {
         ValueBuilder<UserListValue> listBuilder = module.valueBuilderFactory().newValueBuilder( UserListValue.class );

         try
         {
            resetSecurityCredentials();

            String filter = createFilterForFetchGroupWithDn();

            SearchControls userCtls = new SearchControls();
            userCtls.setSearchScope( SearchControls.OBJECT_SCOPE);

            userCtls.setReturningAttributes( createReturnAttributesForGroupQuery() );
            userCtls.setReturningObjFlag( true );
            NamingEnumeration<SearchResult> users = ctx.search( config.configuration().streamflowGroupDn().get(), filter,
                  new String[]{}, userCtls);

            List<UserDetailsValue> userList = new ArrayList<UserDetailsValue>( );
            while( users.hasMore() )
            {
               SearchResult searchResult = users.next();
               Attribute members = searchResult.getAttributes().get( memberAttribute() );
               for( int i=0; i<members.size(); i++ )
               {
                  userList.add( fetchUserDetails( (String)members.get( i ) ) );
               }
            }

         listBuilder.prototype().users().set( userList );

      } catch (NamingException ne )
      {
         logger.debug("Unknown error while importing users: ", ne);
         throw new ResourceException(Status.SERVER_ERROR_INTERNAL, ne);
      }

      return listBuilder.newInstance();
      }

      private UserDetailsValue fetchUserDetails( String dn )
            throws NamingException
      {

         String filter = createFilterForFetchUserWithDn();

         SearchControls ctls = new SearchControls();
         ctls.setSearchScope(SearchControls.OBJECT_SCOPE);
         ctls.setReturningAttributes( createReturnAttributesForUidQuery() );
         ctls.setReturningObjFlag(true);

         NamingEnumeration<SearchResult> enm = ctx.search( dn, filter,
               new String[]
                     { }, ctls);

         UserDetailsValue userDetails = null;

         if (enm.hasMore())
         {
            SearchResult result = enm.next();

            userDetails = createUserDetails(result, null);
         }
         return userDetails;
      }
   }
}
