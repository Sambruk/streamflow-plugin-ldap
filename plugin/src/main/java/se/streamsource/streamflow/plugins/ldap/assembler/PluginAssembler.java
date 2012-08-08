/**
 *
 * Copyright 2009-2012 Jayway Products AB
 *
 * License statement goes here
 */
package se.streamsource.streamflow.plugins.ldap.assembler;

import org.qi4j.api.common.Visibility;
import org.qi4j.bootstrap.Assembler;
import org.qi4j.bootstrap.AssemblyException;
import org.qi4j.bootstrap.ModuleAssembly;
import se.streamsource.streamflow.infrastructure.configuration.FileConfiguration;
import se.streamsource.streamflow.plugins.ldap.LdapPlugin;
import se.streamsource.streamflow.plugins.ldap.LdapPluginConfiguration;
import se.streamsource.streamflow.plugins.ldap.LoggingService;

/**
 * Register the Ldap plugin in the plugin application
 */
public class PluginAssembler
      implements Assembler
{
   public void assemble( ModuleAssembly module ) throws AssemblyException
   {
      module.entities( LdapPluginConfiguration.class ).visibleIn( Visibility.application );

      module.forMixin( LdapPluginConfiguration.class ).declareDefaults().vendor().set( LdapPluginConfiguration.Vendor.not_configured.name() );

      module.services( LdapPlugin.class ).
            identifiedBy( "ldapplugin" ).
            visibleIn( Visibility.application ).
            instantiateOnStartup();

      module.services( FileConfiguration.class ).visibleIn( Visibility.application ).instantiateOnStartup();

      module.services( LoggingService.class ).instantiateOnStartup();
   
   }
}
