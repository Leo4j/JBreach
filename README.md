# JBreach

JBreach is a credential validation tool that can take as input either a user-provided email:password file or a Dehashed API key to extract leaked credentials.

The tool first enumerates all usernames and emails in Active Directory, then tries to match the email addresses against the user-provided wordlist or the Dehashed breached credentials, and finally attempts to validate the credentials.

The script includes features to prevent account lockouts and avoid attempts with already successful credentials.

It also allows users to choose whether they want to only generate a list of breached email:password pairs or if they want to proceed and test Active Directory with that list.

Finally, after a successful login attempt, the tool will check whether the user is a member of any privileged group such as Domain Admins.

### Use the following command to run the tool:

`iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/JBreach/main/JBreach.ps1')`

To access breached credentials, you will need a Dehashed account and API key, or you can provide your own list, or you can use both options.
