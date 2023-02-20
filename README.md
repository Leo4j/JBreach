When asked, provide a list of breached credentials in the format email:password

The script will check each email in the file against a list of users in Active Directory and their associated email

If a match is found, it will test the associated username against the breached password

Finally, the script will output a warning if the username belongs to a group with "Admin" in the name
