*** Settings ***
Resource        resources/utils.resource
Resource        resources/authd.resource
Resource        resources/broker.resource

Test Tags         requires:msentraid
Test Setup        Test Setup
Test Teardown     utils.Test Teardown


*** Keywords ***
Test Setup
    ${passkey_user}=    Get Environment Variable    E2E_PASSKEY_USER    ${EMPTY}
    Set Suite Variable    ${username}    ${passkey_user}
    utils.Test Setup    snapshot=%{BROKER}-installed
    IF    not $username
        Skip    E2E_PASSKEY_USER is not set; skipping the synced-passkey Entra test
    END
    Change Broker Configuration    register_device    true
    Change Broker Configuration    entra_auth    true
    Change Broker Configuration    device_code    false


*** Variables ***
${username}    ${EMPTY}


*** Test Cases ***
Test synced passkey user is offered Entra password fallback
    [Documentation]    Verify that a synced-passkey account is offered the Entra ID
    ...    password fallback instead of being left at a local security-key prompt.
    ...
    ...    The test VM has no local security key. Set E2E_PASSKEY_USER to an Entra
    ...    account with a synced passkey before running this local-only test.

    # GDM accepts the full UPN; machinectl's agetty rejects this tenant user's
    # longer-than-32-character login name before PAM reaches authd.
    Start Log In With Remote User Through GDM    ${username}
    Select Broker Through GDM

    # The password fallback must be the first usable step. A pre-fix broker waits
    # for a local security key here and does not reach this prompt promptly.
    Match Text    Enter your Entra ID password    30    similarity=90

