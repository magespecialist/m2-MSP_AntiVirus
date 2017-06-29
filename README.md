# MSP AntiVirus

A Malware / Virus protection for for Magento 2.<br />
This module is a **ClamAV** interface for malware / virus detection on **POST/PUT** Magento2 requests.<br />
<br />
It adds a strong security layer if you receive **attachment from your customers** or you want to prevent **malicious uploads**.

**Requires ClamAV daemon installed on webserver**.

> Member of **MSP Security Suite**
>
> See: https://github.com/magespecialist/m2-MSP_Security_Suite

## Installing on Magento2:

**1. Install ClamAV (if not present)**

You need ClamAV installed on your server.

On debian/ubuntu-like systems:

`sudo apt-get install clamav-daemon clamav-freshclam`

On CentOS systems:

`sudo yum -y install clamav-server clamav-data clamav-update clamav-server-systemd`

**2. Install MSP AntiVirus using composer**

From command line: 

`composer require msp/antivirus`<br />
`php bin/magento setup:upgrade`

**3. Enable and configure from your Magento backend config**

<img src="https://raw.githubusercontent.com/magespecialist/m2-MSP_AntiVirus/master/screenshots/config.png" />

Adjust the ClamAV socket accordingly to your system. If you are running on Ubuntu Server the default value should work.

NOTE: Remember to flush your cache.

## How to test it

MSP AntiVirus will check any **PUT/POST** Magento operations against known malwares.<br />
If you wish to check the correct module installation, you can try typing the **EICAR signature** in any Magento **POST** form.

> EICAR is a "fake malware" designed to test anti virus systems: http://www.eicar.org/

**Test method:**
Type the below eicar test signature in Magento customer login as password:

`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

If you correctly installed and configured MSP AntiVirus, an emergency stop screen will appear.

## Malware detected

<img src="https://raw.githubusercontent.com/magespecialist/m2-MSP_AntiVirus/master/screenshots/detected.png" />

