/**
 *
 * Copyright 2010 Streamsource AB
 *
 * License statement goes here
 */

package se.streamsource.streamflow.plugins.ldap;

import org.apache.log4j.DailyRollingFileAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.qi4j.api.injection.scope.Service;
import org.qi4j.api.mixin.Mixins;
import org.qi4j.api.service.Activatable;
import org.qi4j.api.service.ServiceComposite;
import se.streamsource.streamflow.infrastructure.configuration.FileConfiguration;

import java.io.File;

/**
 * JAVADOC
 */
@Mixins(LoggingService.Mixin.class)
public interface LoggingService
   extends ServiceComposite, Activatable
{
   class Mixin
      implements Activatable
   {
      @Service
      FileConfiguration fileConfig;

      public void activate() throws Exception
      {
         Logger logger = Logger.getLogger( LoggingService.class );

         // Monitors
         File monitorDirectory = new File(fileConfig.logDirectory(), "monitor");
         monitorDirectory.mkdirs();

         // Access logging
         File accessLog = new File(fileConfig.logDirectory(), "access-ldap.log");
         final Logger accessLogger = Logger.getLogger( "LogService" );
         accessLogger.addAppender( new DailyRollingFileAppender(new PatternLayout("%d %m%n"), accessLog.getAbsolutePath(), "'.'yyyy-ww" ));
         accessLogger.setAdditivity( false );
         logger.info( "Logging HTTP access to:"+accessLog );

         // General logging
         File generalLog = new File(fileConfig.logDirectory(), "streamflow-ldap.log");
         Logger.getRootLogger().addAppender( new DailyRollingFileAppender(new PatternLayout("%d %5p %c{1} - %m%n"), generalLog.getAbsolutePath(), "'.'yyyy-ww" ));
         logger.info( "Logging Streamflow messages:"+generalLog );

      }

      public void passivate() throws Exception
      {
      }
   }
}
