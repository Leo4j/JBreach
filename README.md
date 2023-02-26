# JBreach

JBreach is a credential validation tool that can take as input either a user-provided email:password file or a Dehashed API key to extract leaked credentials.

The tool first enumerates all usernames and emails in Active Directory, then tries to match the email addresses against the user-provided wordlist or the Dehashed breached credentials, and finally attempts to validate the credentials.

The script includes several features to prevent account lockouts and avoid attempts with already used or successful credentials. It also allows users to choose whether they want to only generate a list of breached email:password pairs or if they want to proceed and test Active Directory with that list.

Please note that a Dehashed account and API key are required to access the breached credentials.

### Use the following command to run the tool:

`iex(new-object net.webclient).downloadstring('')`
