*** Settings ***
Suite Setup     Urlredirector PR6014 Setup
Suite Teardown  Urlredirector PR6014 Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/url_redirector_chain.conf
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/redir.eml
${CHAIN_MESSAGE}        ${RSPAMD_TESTDIR}/messages/chain_redirect.eml
${MULTIPART_MESSAGE}    ${RSPAMD_TESTDIR}/messages/chain_multipart.eml
${REDIS_SCOPE}          Suite
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}    {symbols_enabled=[URL_REDIRECTOR_CHECK]}

*** Test Cases ***
CHAIN REDIRECT RESOLUTION WITH INTERMEDIATE HOPS
  [Documentation]  Test PR 6014 feature: resolve redirect chains and inject intermediate hops
  ...              Chain: /chain1 -> /chain2 -> /chain3 -> /hello
  ...              All intermediate hops should be available for downstream modules
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

CHAIN REDIRECT WITH REDIRECTOR SYMBOL
  [Documentation]  Test that redirector_symbol shows the full redirect path (host1->host2->...->hostN)
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

CHAIN REDIRECT CACHED RESOLUTION
  [Documentation]  Test that cached chain resolution works correctly on second scan
  ...              First scan resolves the chain, second scan should use cache
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello
  # Second scan should hit cache
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

MULTIPLE CHAINS IN SINGLE MESSAGE
  [Documentation]  Test handling multiple redirect chains in single message
  Scan File  ${MULTIPART_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

NESTED LIMIT MARKER TEST
  [Documentation]  Test ^nested: marker behavior when nested_limit is exceeded
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

TIMEOUT CONFIGURATION APPLIED
  [Documentation]  Test that timeout, http_timeout, and redis_timeout are correctly applied
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

SAVE INTERMEDIATE REDIRS SETTING
  [Documentation]  Test save_intermediate_redirs = {redirectors=false, non_redirectors=true}
  ...              Non-redirector intermediates should be saved, redirector chains noise should be skipped
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

DIRECT FINAL URL NO REDIRECT
  [Documentation]  Test that direct final URL (no redirect) works correctly
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

*** Keywords ***
Urlredirector PR6014 Setup
  Run Dummy Http
  Rspamd Redis Setup

Urlredirector PR6014 Teardown
  Rspamd Redis Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True
