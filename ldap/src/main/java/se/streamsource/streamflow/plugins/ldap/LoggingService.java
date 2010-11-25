/**
 *
 * Copyright 2009-2010 Streamsource AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
