#!/usr/bin/env python3

import os

banner = """
 __    _             _____               
|  |  |_|___ _ _ _ _|   __|___ _ _ _____ 
|  |__| |   | | |_'_|   __|   | | |     |
|_____|_|_|_|___|_,_|_____|_|_|___|_|_|_|

"""
print(banner)

def search_vuln():
    print("[*] Looking for cron jobs")
    cron_jobs = os.system("ps aux | tee cron.txt")
    cron_read = open("cron.txt", "r")
    cron = cron_read.read()
    cron_list = "chrootkit"
    if cron_list in cron:
        print("[!] Revise the cron jobs")
    else:
      print("[!] Can't find a cron job exploitable\n")
    
    print("[*] Looking for SUID Binaries")
    suid_binaries = os.system("find / -perm -u=s -type f 2>/dev/null | tee suid.txt")
    suid = open("suid.txt" ,"r")
    suid_read = suid.read()
    suid_list = ["ar", "arp", "ash", "atobm", "awk", "base32", "base64", "basenc", "bash", "bridge", "busybox", "capsh", "cat", "chmod", "chown", "chroot", "column", "comm", "cp", "csh", "csplit", "cupsfilter", "curl", "cut", "dash", "date", "dd", "dialog", "diff", "dig", "dmsetup", "docker", "ed", "emacs", "env", "eqn", "expand", "expect", "file", "find", "flock", "fmt", "fold", "gawk", "gdb", "gimp", "grep", "gtester", "hd", "head", "hexdump", "highlight", "hping3", "iconv", "install", "ionice", "ip", "jss", "join", "jq", "jrunscript", "ksh", "ksshell", "ld.so", "less", "logsave", "look", "lua", "lwp-download", "make", "mawk", "more", "mv", "nawk", "nice", "nl", "nmap", "node", "nohup", "od", "openssl", "paste", "perl", "pg", "php", "pr", "python", "readelf", "restic", "rev", "rlwrap", "rsync", "run-parts", "rview", "rvim", "sed", "setarch", "shuf", "soelim", "sort", "sqlite3", "ss", "ssh-keyscan", "start-stop-daemon", "stdbuf", "strace", "strings", "sysctl", "systemctl", "tac", "tail", "taskset", "tbl", "tclsh", "tee", "tftp", "timeout", "troff", "ul", "unexpand", "uniq", "unshare", "update-alternatives", "uudecode", "uuencode", "view", "vigr", "vim", "vimdiff", "vipw", "watch", "wget", "xargs", "xmodmap", "xxd", "xz", "zsh", "zsoeli"]
    
    for i in suid_list:
      if i in suid_read:
        print("[!] Revise SUID Binaries in GTFOBins\n")
      else:
        continue
    
    print("[*] Looking for user privileges")
    users_privileges = os.system("id | tee id.txt")
    user = open("id.txt", "r")
    user_read = user.read()
    user_list = ["(root)", "(sudo)"]
    for i in user_list:
      if i in user_read:
        print("[!] Revise your user privileges")
      else:
        continue
    
    print("\n[*] Looking /etc/passwd file")
    passwd_priv = os.system("ls -la /etc/passwd | tee passwd.txt")
    passwd = open("passwd.txt", "r")
    passwd_read = passwd.read()
    passwd_list = ["-rw-rw-rw-", "-rwxrwxrwx", "-rw-rw-r--", "-rw-r--rw-"]
    for i in passwd_list:
      if i in passwd_read:
        print("[!] File /etc/passwd is writeable")
      else:
        continue
    
    print("\n[*] Looking /etc/shadow file")
    shadow_priv = os.system("ls -la /etc/shadow | tee shadow.txt")
    shadow = open("shadow.txt", "r")
    shadow_read = shadow.read()
    shadow_list = ["-rw-rw-rw-", "-rwxrwxrwx", "-rw-rw-r--", "-rw-r--rw-"]
    for i in shadow_list:
      if i in shadow_read:
        print("[!] File /etc/shadow is writeable")
      else:
        continue
    
    print("\n[*] Looking for /etc/sudoers file")
    sudoers_priv = os.system("ls -la /etc/sudoers | tee sudoers.txt")
    sudoers = open("sudoers.txt", "r")
    sudoers_read = sudoers.read()
    sudoers_list = ["-rw-rw-rw-", "-rwxrwxrwx", "-rw-rw-r--", "-rw-r--rw-"]
    for i in sudoers_list:
      if i in sudoers_read:
        print("[!] File /etc/sudoers is writeable\n")
      else:
        continue
    
    print("\n[*] Looking for Capabilities")
    get_cap = os.system("getcap -r / 2>/dev/null | tee cap.txt")
    cap = open("cap.txt", "r")
    cap_read = cap.read()
    if "cap_setuid" in cap_read:
      print("[!] Revise the Capabilities you can see above\n")
    else:
      print("[!] Can't find any Capabilities (Revise it manually)\n")
    
    print("[*] Looking for Linux Version")
    uname_a = os.system("uname -a")
    print("")
    
    print("[*] Looking for Docker Container")
    search_docker = os.system("ls -la / | tee docker.txt")
    docker = open("docker.txt", "r")
    docker_read = docker.read()
    if "docker" in docker_read:
      print("[!] You seem to be in a Docker Container\n")
    else:
      print("[*] You don't seem to be in a Docker Container\n")
    
    print("[*] Looking for SSH Keys")
    search_ssh = os.system("find / -iname id_rsa 2>/dev/null | tee ssh.txt")
    ssh = open("ssh.txt", "r")
    ssh_read = ssh.read()
    if "id_rsa" in ssh_read:
      print("[!] Found a id_rsa file\n")
    else:
      print("[!] Didn't found a id_rsa file\n")
    
    print("[*] Removing all txt files created")  
    rm_txt = os.system("rm *.txt*")
    print("[!] All files removed successfully")


if __name__ == "__main__":
  search_vuln()
