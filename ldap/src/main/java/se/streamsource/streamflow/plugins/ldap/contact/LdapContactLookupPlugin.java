package se.streamsource.streamflow.plugins.ldap.contact;

import org.qi4j.api.configuration.Configuration;
import org.qi4j.api.injection.scope.Structure;
import org.qi4j.api.injection.scope.This;
import org.qi4j.api.mixin.Mixins;
import org.qi4j.api.service.ServiceComposite;
import org.qi4j.api.value.ValueBuilderFactory;
import org.qi4j.spi.Qi4jSPI;
import org.restlet.data.ChallengeScheme;
import org.restlet.data.MediaType;
import org.restlet.representation.Representation;
import org.restlet.resource.ClientResource;
import se.streamsource.streamflow.server.plugin.contact.ContactList;
import se.streamsource.streamflow.server.plugin.contact.ContactLookup;
import se.streamsource.streamflow.server.plugin.contact.ContactValue;


@Mixins(LdapContactLookupPlugin.Mixin.class)
public interface LdapContactLookupPlugin
      extends ServiceComposite, ContactLookup, Configuration
{

   class Mixin implements ContactLookup
   {

      @This
      Configuration<LdapContactLookupPluginConfiguration> config;

      @Structure
      ValueBuilderFactory vbf;

      @Structure
      private Qi4jSPI spi;

      public ContactList lookup( ContactValue contactTemplate )
      {
         try
         {
            ClientResource clientResource = new ClientResource( config.configuration().url().get() );

            clientResource.setChallengeResponse( ChallengeScheme.HTTP_BASIC, config.configuration().accountname().get(), config.configuration().password().get() );

            // Call plugin
            // TODO
            // setQueryParameters( clientResource.getReference(), contactTemplate );
            Representation result = clientResource.get( MediaType.APPLICATION_JSON );

            // Parse response
            String json = result.getText();
            return vbf.newValueFromJSON( ContactList.class, json );
         } catch (Exception e)
         {

            // Return empty list
            return vbf.newValue( ContactList.class );
         }
      }

   }
}
