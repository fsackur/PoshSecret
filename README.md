# PoshSecret
Securely store and retrieve credentials

# Description
A Powershell module to securely store and retrieve any secret information that can be encoded as a string; commonly, credentials.

This replaces an earlier module that used cmdkey for Windows 7 and Windows.Security.Credentials.PasswordVault for Windows 8+. The complexity of that module increased dramatically with new features. This project runs the same code on all OS versions.

Built-in functions are used for encryption and decryption. It's seamless. Another user cannot decrypt your secrets.

Each secret is stored as a separate file in the user profile, in XML format. The filename is human-readable and derived from the username and name of the secret. The file is in XML format. ONLY THE SECRET IS ENCRYPTED.

# Concepts
Secret - any string data that you wish to securely store.

Username and Name - STORED IN PLAINTEXT - a combination to uniquely identify a secret. Typically, username would be the username, and name would be the resource that the credential is for. However, you aren't bound by this. Name is required; username is optional.

Properties - STORED IN PLAINTEXT - these are additional tags that you can store with the secret.

# Limitations
This is only tested for decryption when you are logged on to the same machine with the same user account that encrypted the secret.

Accessing secrets on a separate machine would require the private key to be shared, which was not in the orginal design goals.

This has only been tested on Windows.

This project takes the security of the built-in functions on faith. If you are of the paranoid persuasion, you should consider this to be no better than the Windows libraries that it calls.

# Apologia
I built this at work. I have dropped the commit history to avoid exposing internal information in the comments - there wasn't much, but I thought it best to err on the safe side.

# Usage:

    Add-PoshSecret -Username "CONTOSO\Bob" -Password "hunter2" -Name "PVScript#00034"
  Stores a credential that can be retrieved using the identifier "PVScript#00034"

    Get-PoshSecret -Username "CONTOSO\bob" -Resource "PVScript#00034" -AsPlaintext
  Gets the credential with the resource identifier "PVScript#00034" and username "CONTOSO\bob". Password will be visible.
  
  You need to run the Get command as the same user that ran the Add command!

