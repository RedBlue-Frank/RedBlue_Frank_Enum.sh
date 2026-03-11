# RedBlue_Frank_Enum.sh
RedBlue_Frank_ADenum is an interactive Bash-based Active Directory enumeration framework. It automates the use of NetExec and Impacket to perform credential validation, protocol mapping, user enumeration, roasting attacks (Kerberoasting/AS-REP), and BloodHound data collection through a streamlined menu interface.

#Features##

Credential Validation: Automatically tests provided credentials via SMB before proceeding.

Protocol Mapping: Quickly checks reachability for SMB, LDAP, WinRM, and RDP.

User Discovery: Performs RID Brute Forcing and LDAP user extraction.

Vulnerability Scanning: Includes checks for Zerologon (CVE-2020-1472), GPP Autologon, and ADCS (Active Directory Certificate Services).

Attack Automation: * Kerberoasting: Targeted and "Blind" (no-preauth) roasting.

AS-REP Roasting: Identifies accounts with "Do not require Kerberos preauthentication" set.

BloodHound Integration: Automates the collection of AD objects and relations into a ZIP file ready for ingest.

"Run All" Mode: A one-click automated sweep of the environment.

##Prerequisites##

The script requires the following tools to be installed and available in your $PATH:

NetExec (nxc)

Impacket (GetUserSPNs.py, GetNPUsers.py)

Standard Linux utilities: awk, grep, getent


##Usage##

Clone the repository:

git clone https://github.com/YourUsername/RedBlue_Frank_ADenum.git
cd RedBlue_Frank_ADenum

Make the script executable:
chmod +x RedBlue_Frank_ADenum.sh

Run the script:
./RedBlue_Frank_ADenum.sh

<img width="1401" height="739" alt="image" src="https://github.com/user-attachments/assets/c3850b30-1d56-4072-b46f-0bcd0645d535" />

<img width="1392" height="727" alt="image" src="https://github.com/user-attachments/assets/7b01d1fd-fd4e-4d78-9ee6-b4dfa2d8200c" />

