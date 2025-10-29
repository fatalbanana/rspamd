*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${SETTINGS_DNS}       {symbols_enabled = [SIMPLE_DNS, SIMPLE_DNS_SYNC]}
${SETTINGS_DNS_TCP}   {symbols_enabled = [SIMPLE_DNS_TCP]}

*** Test Cases ***
Simple DNS request
  Scan File  ${MESSAGE}  To-Resolve=example.com
  ...  Settings=${SETTINGS_DNS}
  Expect Symbol With Exact Options  DNS_SYNC  93.184.216.34
  Expect Symbol With Exact Options  DNS  93.184.216.34

Faulty DNS request
  Scan File  ${MESSAGE}  To-Resolve=not-resolvable.com
  ...  Settings=${SETTINGS_DNS}
  Expect Symbol With Exact Options  DNS_SYNC_ERROR  requested record is not found
  Expect Symbol With Exact Options  DNS_ERROR  requested record is not found

# Test DNS over TCP with large TXT records (e.g., github.com has ~1.5KB TXT data)
# This exercises the DNS TCP code path. The fix in contrib/librdns/resolver.c
# corrected partial write handling by properly accounting for the 2-byte size prefix.
# While partial writes are hard to reproduce reliably without kernel manipulation,
# this test validates the TCP path works correctly with large responses.
DNS over TCP with large TXT record
  Scan File  ${MESSAGE}  To-Resolve=github.com
  ...  Settings=${SETTINGS_DNS_TCP}
  Expect Symbol  DNS_TCP

