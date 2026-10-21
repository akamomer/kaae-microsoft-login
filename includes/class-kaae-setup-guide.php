<?php
defined( 'ABSPATH' ) || exit;

/** Administrator-facing instructions; rendering never changes configuration. */
final class KAAE_MS_Setup_Guide {
    public static function render( string $callback, string $profile_url ): void {
        ?>
        <details class="postbox" style="max-width:960px;margin-top:20px;padding:16px 24px;box-sizing:border-box">
            <summary style="cursor:pointer;font-size:16px;font-weight:600;line-height:1.5">Microsoft setup — start here</summary>
            <p>Complete these steps using KAAE’s Microsoft organization account. You need permission to register an application in your organization’s Microsoft Entra directory. If registration is unavailable, ask your Microsoft 365 administrator to complete steps 1–4.</p>
            <p><strong>During initial setup, leave “Require Microsoft sign-in for all users” off until your administrator’s Microsoft login works.</strong> If it is already enforced, keep your current administrator session open while changing onboarding settings and testing the external-user exception.</p>
            <ol style="margin-left:24px">
                <li>
                    <h3>Register the KAAE application</h3>
                    <p>Open the <a href="https://entra.microsoft.com/" target="_blank" rel="noopener noreferrer">Microsoft Entra admin center</a>. Make sure you are in KAAE’s directory, then open <strong>Entra ID → App registrations → New registration</strong>.</p>
                    <ul style="list-style:disc;margin-left:24px">
                        <li><strong>Name:</strong> enter <code>KAAE WordPress Sign-in</code>.</li>
                        <li><strong>Supported account types:</strong> choose <strong>Single tenant only — your KAAE organization</strong> (also called “Accounts in this organizational directory only”).</li>
                        <li>Select <strong>Register</strong>. Use KAAE’s workforce directory for staff accounts.</li>
                    </ul>
                </li>
                <li>
                    <h3>Add this site’s Web redirect URI</h3>
                    <p>Inside the app registration, open <strong>Authentication → Redirect URI configuration → Add Redirect URI</strong>, then select <strong>Web</strong>. Some portal versions show <strong>Add a platform → Web</strong>. Paste the exact address below and save/configure the platform:</p>
                    <label for="kaae-ms-guide-callback"><strong>Redirect URI for this WordPress installation</strong></label>
                    <input id="kaae-ms-guide-callback" class="large-text code" type="text" readonly value="<?php echo esc_attr( $callback ); ?>" style="margin-top:6px;max-width:100%">
                    <p class="description">Copy the complete address, including <code>?action=kaae_ms_callback</code>. Use the value shown on this page, including any www prefix or installation path. Do not add a trailing slash.</p>
                    <p>This plugin uses the authorization code flow. Leave the implicit-grant access-token and ID-token checkboxes off, and public client flows disabled. A front-channel logout URL is not required for this setup.</p>
                    <p><strong>For form.kaae.org:</strong> the same app registration can contain a second Web redirect URI. Install the plugin there, open its settings page, and copy that installation’s exact redirect URI into this same application. Configure each WordPress installation separately; account connections are separate too.</p>
                </li>
                <li>
                    <h3>Copy the two application IDs</h3>
                    <p>Return to the app registration’s <strong>Overview</strong> page. Copy these values into the matching fields below:</p>
                    <table class="widefat striped" style="max-width:800px">
                        <thead><tr><th scope="col">Microsoft Overview field</th><th scope="col">Plugin field</th></tr></thead>
                        <tbody>
                            <tr><td>Directory (tenant) ID</td><td>Microsoft tenant ID</td></tr>
                            <tr><td>Application (client) ID</td><td>Application client ID</td></tr>
                        </tbody>
                    </table>
                    <p>Both are IDs in the form <code>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</code>. The Object ID and your email domain are different values.</p>
                </li>
                <li>
                    <h3>Create and save a client secret</h3>
                    <p>Open <strong>Certificates &amp; secrets → Client secrets → New client secret</strong>. Enter a description, choose an expiry that follows KAAE’s policy, and select <strong>Add</strong>.</p>
                    <p>Copy the new secret’s <strong>Value</strong> immediately into the <strong>Client secret</strong> field below. Microsoft displays the value only once. The <strong>Secret ID</strong> is different and will not work. Record the expiry in your organization’s credential-management process so the secret can be renewed before sign-in stops working.</p>
                    <p>Keep the secret in your approved credential store and this site’s configuration; do not paste it into chat, email, GitHub, or screenshots. The plugin leaves this field empty after saving; an empty field on later saves keeps the stored secret.</p>
                    <p class="description">This version supports client-secret authentication only. Microsoft recommends certificate or federated credentials for production; those credential types are not implemented in this version. <a href="https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials" target="_blank" rel="noopener noreferrer">Microsoft credential guidance</a>.</p>
                </li>
                <li>
                    <h3>Choose manual connection or automatic staff accounts</h3>
                    <p>Leave <strong>Require Microsoft sign-in for all users</strong> unchecked and select <strong>Save Changes</strong> below. GitHub configuration is optional and can stay blank during Microsoft setup.</p>
                    <p>Open <a href="<?php echo esc_url( $profile_url ); ?>">Users → Profile</a>. Your WordPress email must match your Microsoft work <strong>sign-in address</strong> exactly and end in <code>@kaae.org</code>. A mailbox alias can differ from your Microsoft sign-in address.</p>
                    <p>For <strong>manual connection</strong>, under <strong>KAAE Microsoft account</strong>, select <strong>Connect Microsoft account</strong> and choose your own KAAE work account. This connects an existing WordPress user.</p>
                    <p>For <strong>automatic staff accounts</strong>, open the Microsoft app registration’s <strong>API permissions → Add a permission → Microsoft Graph → Delegated permissions</strong>. Add <strong>User.Read</strong> (it may already be present). Have your Microsoft administrator grant consent if your organization requires it. Then enable <strong>Automatically connect existing KAAE users and create new staff as Subscribers</strong> below and save.</p>
                    <p>With automatic accounts enabled, staff can choose Microsoft sign-in directly: the plugin checks the signed-in person’s directory Member status and canonical <code>@kaae.org</code> user principal name through Microsoft Graph. It connects an exact existing WordPress email match while preserving its role, or creates a new Subscriber. A connection to a different Microsoft identity is never overwritten. No bulk import is performed; each account is handled on that person’s successful sign-in.</p>
                    <p>Manual mode requests <code>openid profile email</code>. Automatic mode also requests delegated <code>User.Read</code> for the signed-in person. Neither mode needs mail, calendar, directory-wide, or Graph application permissions. Application assignment and Conditional Access policies must allow the staff who will use it.</p>
                    <p><strong>External users:</strong> enter each existing external WordPress user’s email on a separate line in <strong>External user password exceptions</strong> below and save. Only the listed users can retain password sign-in while Microsoft-only mode is enforced. Your previous single-user exception appears automatically. This list does not create WordPress accounts; external users must already exist.</p>
                </li>
                <li>
                    <h3>Test before requiring Microsoft sign-in</h3>
                    <p>Keep this administrator session open. In a separate browser or private window, visit this site’s login page, select <strong>Sign in with Microsoft</strong>, and complete any Microsoft and WordPress security challenges. Confirm that you reach the correct WordPress account with its existing permissions.</p>
                    <p>In manual mode, have every required staff member connect their own account on each site. In automatic mode, test a matching existing staff account and a new staff account; the new account must have Subscriber permissions. Also test the selected external user’s password login. Then enable <strong>Require Microsoft sign-in for all users</strong>. The plugin requires a successful Microsoft authentication test for your connected administrator account using the current credential configuration before that setting can be saved.</p>
                    <p>Connected users can also choose <strong>Disable password sign-in for my account</strong> in Users → Profile after testing Microsoft sign-in, then select <strong>Update Profile</strong>. Clearing that preference does not override a site-wide Microsoft-only rule.</p>
                    <p>With enforcement enabled, only the listed external accounts can use password login. Remove an email from the list and save to revoke that account’s exception for future logins. Without automatic accounts, unconnected staff cannot sign in. Application-password API clients stop authenticating for everyone while enforcement is on. Existing sessions stay signed in. Keep a trusted server administrator available for recovery.</p>
                </li>
            </ol>
            <details style="margin-top:20px">
                <summary><strong>Help with common setup problems</strong></summary>
                <ul style="list-style:disc;margin-left:24px">
                    <li><strong>AADSTS50011 / redirect URI mismatch:</strong> compare the Web redirect URI in Microsoft with the complete value shown above. Check the domain, www prefix, path, query string and trailing slash.</li>
                    <li><strong>Invalid client secret:</strong> paste the secret Value, not the Secret ID. Check that the secret is unexpired and belongs to this app registration.</li>
                    <li><strong>Administrator approval or assignment required:</strong> ask KAAE’s Microsoft administrator to review consent and the Enterprise application’s user assignments.</li>
                    <li><strong>WordPress email mismatch:</strong> compare your WordPress profile email with your Microsoft work sign-in address. A different mailbox alias will not connect.</li>
                    <li><strong>Account is not connected:</strong> in manual mode, sign in normally and connect Microsoft from your own profile. If password login is blocked, contact the administrator. Automatic mode connects matching staff after directory verification.</li>
                    <li><strong>Directory verification failed:</strong> check that User.Read is a delegated Microsoft Graph permission, consent is approved, and the server can reach graph.microsoft.com. Guest accounts or non-KAAE user principal names are not eligible for automatic accounts.</li>
                    <li><strong>External user cannot use a password:</strong> add their existing WordPress email to the exceptions list on its own line and save. Only listed accounts receive exceptions; a personal password-disable preference still takes priority. If any entry is invalid, the entire save is rejected and existing settings remain unchanged.</li>
                    <li><strong>Expired request or browser verification failed:</strong> start again in the same browser, allow this site’s cookies, and complete the process within ten minutes.</li>
                    <li><strong>Login button missing after saving:</strong> check that both IDs and a secret are configured, and that the site recognizes its connection as HTTPS. A server administrator can check PHP OpenSSL and proxy HTTPS settings.</li>
                </ul>
            </details>
            <p style="margin-top:20px">Microsoft instructions:
                <a href="https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app" target="_blank" rel="noopener noreferrer">Register an application</a> ·
                <a href="https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-redirect-uri" target="_blank" rel="noopener noreferrer">Add a redirect URI</a> ·
                <a href="https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc" target="_blank" rel="noopener noreferrer">Sign-in permissions</a>
            </p>
        </details>
        <?php
    }
}
