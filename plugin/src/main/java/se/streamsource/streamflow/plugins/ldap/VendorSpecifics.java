/**
 *
 * Copyright 2009-2012 Jayway Products AB
 *
 * License statement goes here
 */
package se.streamsource.streamflow.plugins.ldap;

/**
 * Class providing a method interface for vendor specific ldap attributes.
 */
public interface VendorSpecifics
{
   String createFilterForUidQuery();

   String createFilterForFetchUserWithDn();

   String createFilterForGroupOfNames();

   String memberAttribute();

   String uidAttribute();

   String entryUUIDAttribute();

   String createFilterForUniqueMember();
}
