package se.streamsource.streamflow.plugins.ldap.helper;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;

public interface AttributesMapper<T>
{

   public T mapFromAttribute(Attributes attributes) throws NamingException;

}
