package se.streamsource.streamflow.plugins.ldap.helper;

import javax.naming.NamingException;
import javax.naming.directory.SearchResult;

public interface SearchResultMapper<T>
{

   public T mapFromSearchResult(SearchResult result) throws NamingException;
}
