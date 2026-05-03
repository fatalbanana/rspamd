*** Settings ***
Suite Setup     Urlredirector Chain Setup
Suite Teardown  Urlredirector Chain Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/url_redirector_chain.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/chain_redirect.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled=[URL_REDIRECTOR_CHECK]}

*** Test Cases ***
INTERMEDIATE HOP INJECTION
  [Documentation]  Test that intermediate hops in redirect chains are injected into the task
  ...              for scanning by downstream modules (phishing, SURBL, etc.)
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

INTERMEDIATE HOP CACHING
  [Documentation]  Test that cached intermediate hops are properly handled with markers
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

NESTED MARKER HANDLING
  [Documentation]  Test that ^nested: markers are handled correctly for limit exceeded
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

CHAIN AWARE CACHE
  [Documentation]  Test chain-aware cache with per-hop Redis entries
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

TIMEOUT HANDLING
  [Documentation]  Test separate timeout configuration (timeout, http_timeout, redis_timeout)
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

SAVE INTERMEDIATE REDIRECTS CONFIG
  [Documentation]  Test save_intermediate_redirs setting with redirectors/non_redirectors options
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

HOST PATH IN SYMBOL
  [Documentation]  Test that redirector_symbol shows full host path (host1->host2->...->hostN)
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

*** Keywords ***
Urlredirector Chain Setup
  Run Dummy Http
  Rspamd Redis Setup

Urlredirector Chain Teardown
  Rspamd Redis Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True
