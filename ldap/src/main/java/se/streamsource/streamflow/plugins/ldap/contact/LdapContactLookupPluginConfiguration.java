package se.streamsource.streamflow.plugins.ldap.contact;

import org.qi4j.api.common.UseDefaults;
import org.qi4j.api.configuration.ConfigurationComposite;
import org.qi4j.api.property.Property;

/**
 * Configuration for the Ldap Plugin. The values are set using the JMX interface
 */
public interface LdapContactLookupPluginConfiguration
      extends ConfigurationComposite
{
   @UseDefaults
   Property<String> url();

   @UseDefaults
   Property<String> accountname();

   @UseDefaults
   Property<String> password();
}
