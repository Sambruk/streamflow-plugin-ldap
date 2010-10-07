package se.streamsource.streamflow.commercial.ldap.contact;

import org.junit.Test;
import org.qi4j.api.common.Visibility;
import org.qi4j.api.injection.scope.Service;
import org.qi4j.bootstrap.AssemblyException;
import org.qi4j.bootstrap.ModuleAssembly;
import org.qi4j.test.AbstractQi4jTest;
import se.streamsource.streamflow.plugins.ldap.contact.LdapContactLookupPlugin;
import se.streamsource.streamflow.plugins.ldap.contact.LdapContactLookupPluginConfiguration;
import se.streamsource.streamflow.server.plugin.contact.ContactLookup;

/**
 * Test for LdapContactLookup plugin. Using an in-memory Apache Ds.
 */
public class LdapContactLookupPluginTest extends AbstractQi4jTest
{
   public void assemble( ModuleAssembly module ) throws AssemblyException
   {
      module.layerAssembly().applicationAssembly().setName( getClass().getSimpleName() );
      module.addServices( LdapContactLookupPlugin.class ).
            identifiedBy( "ldapcontactlookup" ).
            visibleIn( Visibility.application ).
            instantiateOnStartup();

      module.addEntities( LdapContactLookupPluginConfiguration.class ).visibleIn( Visibility.application );
   }

   @Service
   ContactLookup contactLookup;

   @Test
   public void testLookup()
   {
      contactLookup.lookup( null );
   }

}
