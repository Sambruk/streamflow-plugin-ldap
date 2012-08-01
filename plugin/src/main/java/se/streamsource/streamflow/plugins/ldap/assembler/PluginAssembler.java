/**
 *
 * Copyright 2010 Streamsource AB
 *
 * License statement goes here
 */

package se.streamsource.streamflow.plugins.ldap.assembler;

import org.qi4j.api.common.Visibility;
import org.qi4j.bootstrap.Assembler;
import org.qi4j.bootstrap.AssemblyException;
import org.qi4j.bootstrap.ModuleAssembly;
import se.streamsource.streamflow.infrastructure.configuration.FileConfiguration;
import se.streamsource.streamflow.plugins.ldap.LoggingService;
import se.streamsource.streamflow.plugins.ldap.authentication.LdapAuthenticatePlugin;
import se.streamsource.streamflow.plugins.ldap.authentication.LdapAuthenticatePluginConfiguration;

/**
 * Register the Ldap plugin in the plugin application
 */
public class PluginAssembler
      implements Assembler
{
   public void assemble( ModuleAssembly module ) throws AssemblyException
   {
      module.entities( LdapAuthenticatePluginConfiguration.class ).visibleIn( Visibility.application );

      module.forMixin( LdapAuthenticatePluginConfiguration.class ).declareDefaults().name().set( LdapAuthenticatePluginConfiguration.Name.not_configured.name() );

      module.services( LdapAuthenticatePlugin.class ).
            identifiedBy( "ldapauthenticationplugin" ).
            visibleIn( Visibility.application ).
            instantiateOnStartup();

      module.services( FileConfiguration.class ).visibleIn( Visibility.application ).instantiateOnStartup();

      module.services( LoggingService.class ).instantiateOnStartup();
   
   }
}
