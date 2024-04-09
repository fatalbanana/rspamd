*** Grow Factor ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/grow_factor.conf
${HAM_MESSAGE}          ${RSPAMD_TESTDIR}/messages/ham.eml
${RSPAMD_SCOPE}         Suite

*** Keywords ***
CHECK BASIC
  Scan File  ${HAM_MESSAGE}
  Check Required Score  20
  Expect Symbols With Scores
