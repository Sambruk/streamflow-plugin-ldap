/**
 *
 * Copyright 2009-2012 Jayway Products AB
 *
 * License statement goes here
 */
package se.streamsource.streamflow.plugins.ldap;

import org.qi4j.api.common.UseDefaults;
import org.qi4j.api.configuration.ConfigurationComposite;
import org.qi4j.api.property.Property;

public interface LdapPluginConfiguration extends ConfigurationComposite
{

   public enum Vendor
   {
      not_configured, ad, edirectory, apacheds
    }
   
   /**
    * Vendor of the server to use, currently supporting 'ad' (Active Directory) and 'edirectory' (Novell eDirectory), Apacheds
    * @return
    */
   @UseDefaults
   Property<String> vendor();
   
   /**
    * The URL to the Ldap server
    *
    * @return
    */
   @UseDefaults
   Property<String> url();
   
   /**
    * The username for the system account to use for queries in ldap.
    * Leave empty if the queries are done anonymously.
    * @return
    */
   @UseDefaults
   Property<String> username();
   
   /**
    * The password for the system account to use for queries in ldap.
    * Leave empty if the queries are done anonymously.
    * @return
    */
   @UseDefaults
   Property<String> password();
   
   /**
    * The cn for the search for users i.e. 'ou=your_user_dir, o=your_org'
    * @return
    */
   @UseDefaults
   Property<String> userSearchbase();
   
   /**
    * The attribute name for full name i.e. 'givenName'
    * @return
    */
   @UseDefaults
   Property<String> nameAttribute();

   /**
    * The attribute name for phonenumber i.e. 'telephoneNumber'
    * @return
    */
   @UseDefaults
   Property<String> phoneAttribute();

   /**
    * The attribute name for emailaddress i.e. 'mail'
    * @return
    */
   @UseDefaults
   Property<String> emailAttribute();

   /**
    * The cn for the group membership search i.e. 'ou=groups,ou=streamflow,o=your_org'
    * @return
    */
   @UseDefaults
   Property<String> groupSearchbase();

   /**
    * The distinguished name for streamflow users group, i.e. 'cn=users,ou=streamflow,o=your_org'
    * @return
    */
   @UseDefaults
   Property<String> streamflowUsersDn();

}
