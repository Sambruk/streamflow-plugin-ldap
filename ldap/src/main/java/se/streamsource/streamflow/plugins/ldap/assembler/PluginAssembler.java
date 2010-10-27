package se.streamsource.streamflow.plugins.ldap.assembler;

import org.qi4j.api.common.Visibility;
import org.qi4j.bootstrap.Assembler;
import org.qi4j.bootstrap.AssemblyException;
import org.qi4j.bootstrap.ModuleAssembly;

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
      module.addEntities( LdapAuthenticatePluginConfiguration.class ).visibleIn( Visibility.application );

      module.addServices( LdapAuthenticatePlugin.class ).
            identifiedBy( "authentication" ).
            visibleIn( Visibility.application ).
            instantiateOnStartup();

   
   }
}
