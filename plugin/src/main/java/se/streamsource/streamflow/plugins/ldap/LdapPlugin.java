/**
 *
 * Copyright 2009-2012 Jayway Products AB
 *
 * License statement goes here
 */
package se.streamsource.streamflow.plugins.ldap;

import org.apache.commons.collections.CollectionUtils;
import org.qi4j.api.configuration.Configuration;
import org.qi4j.api.injection.scope.Structure;
import org.qi4j.api.injection.scope.This;
import org.qi4j.api.mixin.Mixins;
import org.qi4j.api.service.Activatable;
import org.qi4j.api.service.ServiceComposite;
import org.qi4j.api.structure.Module;
import org.qi4j.api.util.Function;
import org.qi4j.api.util.Iterables;
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
import se.streamsource.streamflow.server.plugin.ldapimport.GroupMemberDetailValue;
import se.streamsource.streamflow.server.plugin.ldapimport.LdapImporter;
import se.streamsource.streamflow.server.plugin.ldapimport.UserListValue;
import se.streamsource.streamflow.util.Strings;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.InvalidNameException;
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
 * Ldap Plugin class for fetching and authenticating users and groups against an Ldap vendor.
 * */
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

      private VendorSpecifics vendorSpecifics;

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
            switch (LdapPluginConfiguration.Vendor.valueOf( config.configuration().vendor().get() ) )
            {
               case ad:
                  vendorSpecifics = new MicrosoftActiveDirectorySpecifics();
                  break;
               case edirectory:
                  vendorSpecifics = new NovellEdirectorySpecifics();
                  break;
               case apacheds:
                  vendorSpecifics = new ApacheDsSpecifics();
                  break;
               default:
                  vendorSpecifics = null;
            }
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
               || Strings.empty(config.configuration().groupSearchbase().get()))
         {
            return false;
         }
         return true;
      }

      protected String[] createReturnAttributesForGroupQuery()
      {
         return new String[] { config.configuration().nameAttribute().get(),
               vendorSpecifics.memberAttribute() };
      }

      protected String[] createReturnAttributesForUidQuery()
      {
         return new String[]
               {vendorSpecifics.uidAttribute(),
                     config.configuration().nameAttribute().get(),
                     config.configuration().emailAttribute().get(),
                     config.configuration().phoneAttribute().get()};
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

            String filter = vendorSpecifics.createFilterForUidQuery();

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

         String[] returningAttributes = new String[] { vendorSpecifics.memberAttribute() };
         String filter = vendorSpecifics.createFilterForUniqueMember();

         groupCtls.setReturningAttributes(returningAttributes);
         groupCtls.setReturningObjFlag(true);
         NamingEnumeration<SearchResult> groups = ctx.search( config.configuration().streamflowUsersDn().get(), filter,
               new String[]
                     {dn}, groupCtls );
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
         Attribute uid  = result.getAttributes().get( vendorSpecifics.uidAttribute() );

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
            groupCtls.setSearchScope( SearchControls.SUBTREE_SCOPE );

            String[] returningAttributes = createReturnAttributesForGroupQuery();
            String filter = vendorSpecifics.createFilterForGroupOfNames();

            groupCtls.setReturningAttributes( returningAttributes );
            groupCtls.setReturningObjFlag( true );
            NamingEnumeration<SearchResult> groups = ctx.search( config.configuration().groupSearchbase().get(), filter,
                  new String[]{}, groupCtls );

            List<GroupDetailsValue> groupsList = new ArrayList<GroupDetailsValue>();
            ValueBuilder<GroupDetailsValue> groupBuilder = module.valueBuilderFactory().newValueBuilder( GroupDetailsValue.class );
            while (groups.hasMore())
            {
               SearchResult searchResult = groups.next();

               groupBuilder.prototype().id().set( searchResult.getNameInNamespace() );

               Attribute name = searchResult.getAttributes().get( config.configuration().nameAttribute().get() );
               if (name == null)
               {
                  logger.error( "Seems attribute browsing is prohibited. Check user rights for user in config." );
                  throw new ResourceException( Status.CLIENT_ERROR_UNAUTHORIZED );
               }

               groupBuilder.prototype().name().set( (String) name.get() );

               Attribute members = searchResult.getAttributes().get( vendorSpecifics.memberAttribute() );
               List<String> membersDN = new ArrayList<String>();
               for (int i = 0; i < members.size(); i++)
               {
                  membersDN.add( (String) members.get( i ) );
               }

               Iterable<GroupMemberDetailValue> memberIterable = Iterables.map( new Function<String, GroupMemberDetailValue>()
               {
                  ValueBuilder<GroupMemberDetailValue> groupMemberBuilder = module.valueBuilderFactory().newValueBuilder( GroupMemberDetailValue.class );

                  public GroupMemberDetailValue map( String dn )

                  {
                     GroupMemberDetailValue result = null;
                     try
                     {
                        LdapName ldapName = new LdapName( dn );
                        for (Rdn rdn : ldapName.getRdns())
                        {
                           if (vendorSpecifics.uidAttribute().equals( rdn.getType() ))
                           {
                              groupMemberBuilder.prototype().memberType().set( GroupMemberDetailValue.Type.user );
                              groupMemberBuilder.prototype().id().set( (String) rdn.getValue() );
                              result = groupMemberBuilder.newInstance();
                           }
                        }
                        if (result == null)
                        {
                           groupMemberBuilder.prototype().memberType().set( GroupMemberDetailValue.Type.group );
                           groupMemberBuilder.prototype().id().set( dn );
                           result = groupMemberBuilder.newInstance();
                        }
                     } catch (InvalidNameException ine)
                     {
                        logger.debug( "Unknown error while importing groups: ", ine );
                        throw new ResourceException( Status.SERVER_ERROR_INTERNAL, ine );
                     }

                     return result;
                  }

               }, membersDN );


               List<GroupMemberDetailValue> memberList = new ArrayList<GroupMemberDetailValue>();
               CollectionUtils.addAll( memberList, memberIterable.iterator() );

               groupBuilder.prototype().members().set( memberList );
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

            String filter = vendorSpecifics.createFilterForGroupOfNames();

            SearchControls userCtls = new SearchControls();
            userCtls.setSearchScope( SearchControls.OBJECT_SCOPE);

            userCtls.setReturningAttributes( createReturnAttributesForGroupQuery() );
            userCtls.setReturningObjFlag( true );
            NamingEnumeration<SearchResult> users = ctx.search( config.configuration().streamflowUsersDn().get(), filter,
                  new String[]{}, userCtls);

            List<UserDetailsValue> userList = new ArrayList<UserDetailsValue>( );
            while( users.hasMore() )
            {
               SearchResult searchResult = users.next();
               Attribute members = searchResult.getAttributes().get( vendorSpecifics.memberAttribute() );
               if (members != null)
               {
                  logger.error( "Seems attribute browsing is prohibited. Check user rights for user in config." );
                  throw new ResourceException( Status.CLIENT_ERROR_UNAUTHORIZED );
               }

               for (int i = 0; i < members.size(); i++)
               {
                  userList.add( fetchUserDetails( (String) members.get( i ) ) );
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

         String filter = vendorSpecifics.createFilterForFetchUserWithDn();

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

   class ApacheDsSpecifics implements VendorSpecifics
   {
      public String createFilterForUidQuery()
      {
         return "(&(objectClass=inetOrgPerson)(uid={0}))";
      }

      public String createFilterForFetchUserWithDn()
      {
         return "(objectClass=inetOrgPerson)";
      }

      public String createFilterForGroupOfNames()
      {
         return "(objectClass=groupOfUniqueNames)";
      }

      public String memberAttribute()
      {
         return "uniqueMember";
      }

      public String uidAttribute()
      {
         return "uid";
      }

      public String entryUUIDAttribute()
      {
         return "entryUUID";
      }

      public String createFilterForUniqueMember()
      {
         return "(uniqueMember={0})";
      }
   }

   class NovellEdirectorySpecifics implements VendorSpecifics
   {
      public String createFilterForUidQuery()
      {
         return "(&(objectClass=inetOrgPerson)(uid={0}))";
      }

      public String createFilterForFetchUserWithDn()
      {
         return "(objectClass=inetOrgPerson)";
      }

      public String createFilterForGroupOfNames()
      {
         return "(objectClass=groupOfNames)";
      }

      public String memberAttribute()
      {
         return "member";
      }

      public String uidAttribute()
      {
         return "uid";
      }

      public String entryUUIDAttribute()
      {
         return "GUID";
      }

      public String createFilterForUniqueMember()
      {
         return "(member={0})";
      }
   }

   class MicrosoftActiveDirectorySpecifics implements VendorSpecifics
   {
      public String createFilterForUidQuery()
      {
         return "(&(objectclass=person)(uid={0}))";
      }

      public String createFilterForFetchUserWithDn()
      {
         return "(objectclass=person)";
      }

      public String createFilterForGroupOfNames()
      {
         return "(objectclass=groupOfNames)";
      }

      public String memberAttribute()
      {
         return "member";
      }


      public String uidAttribute()
      {
         return "uid";
      }

      public String entryUUIDAttribute()
      {
         return "objectGUID";
      }

      public String createFilterForUniqueMember()
      {
         return "(member={0})";
      }
   }
}
