*** Settings ***
Suite Setup     Urlredirector Setup
Suite Teardown  Urlredirector Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/url_redirector.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/redir.eml
${CHAIN_MESSAGE}   ${RSPAMD_TESTDIR}/messages/chain_redirect.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled=[URL_REDIRECTOR_CHECK]}

*** Test Cases ***
RESOLVE URLS
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

RESOLVE URLS CACHED
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

RESOLVE CHAIN WITH INTERMEDIATE HOPS
  [Documentation]  Test that redirect chains with intermediate hops are resolved correctly
  ...              Chain: /chain1 -> /chain2 -> /chain3 -> /hello
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

RESOLVE CHAIN CACHED
  [Documentation]  Test that cached chains with intermediate hops work correctly
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

*** Keywords ***
Urlredirector Setup
  Run Dummy Http
  Rspamd Redis Setup

Urlredirector Teardown
  Rspamd Redis Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True
