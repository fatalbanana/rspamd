*** Settings ***
Suite Setup      DNS TCP Slow Setup
Suite Teardown   DNS TCP Slow Teardown
Test Setup       Rspamd Setup
Test Teardown    Rspamd Teardown
Library          Process
Library          ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource         ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables        ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/dns_slow.conf
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${SETTINGS_DNS_SLOW}   {symbols_enabled = [SIMPLE_DNS_TCP_SLOW]}
${DNS_SLOW_PORT}       15353

*** Test Cases ***
# Test DNS over TCP with slow custom server that triggers partial writes
# This uses a mock DNS server (dummy_dns_slow.py) that deliberately sends
# responses in 1-byte chunks with delays to reliably reproduce partial write scenarios.
# The fix: ntohs(oc->next_write_size) + sizeof(oc->next_write_size) <= oc->cur_write
# Without the fix, the output buffer would be freed prematurely during partial writes.
DNS over TCP with slow server triggering partial writes
  Scan File  ${MESSAGE}  To-Resolve=slowtest.example.com
  ...  Settings=${SETTINGS_DNS_SLOW}
  Expect Symbol  DNS_TCP_SLOW

*** Keywords ***
DNS TCP Slow Setup
  Run Dummy DNS Slow
  Rspamd Setup

DNS TCP Slow Teardown
  Rspamd Teardown
  Terminate Process  ${DUMMY_DNS_SLOW_PROC}
  Wait For Process  ${DUMMY_DNS_SLOW_PROC}

Run Dummy DNS Slow
  ${result} =  Start Process  ${RSPAMD_TESTDIR}/util/dummy_dns_slow.py  ${DNS_SLOW_PORT}
  Wait Until Created  /tmp/dummy_dns_slow.pid  timeout=5s
  Set Suite Variable  ${DUMMY_DNS_SLOW_PROC}  ${result}
