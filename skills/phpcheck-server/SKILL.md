---
name: phpcheck-server
description: Check PHP2Shell patch status with local or server access.
---

# Check PHP2Shell patch status

Check for fixes covering both CVE-2026-109618 and CVE-2026-109619.
Do not run exploit probes.

## Identify the serving installation

Identify the PHP installation serving the site, including its container if
applicable. The default CLI PHP may differ from PHP-FPM or Apache's PHP module.

Inspect the serving binary or Apache module and its owning package directly.
Determine the OS release and package provider before choosing an advisory.

## Check patch status

Compare the full package revision against vendor guidance covering both CVEs.
An older upstream version alone does not prove vulnerability. Configuration
settings alone do not establish patch status.

The fixed package versions below were verified on 2026-10-22. They apply only
to official packages for the listed OS release and PHP branch. Use the listed
version or a later version from the same vendor release and stream.

### Debian

Use `dpkg-query` to read the full installed package version and
`dpkg --compare-versions` for comparisons. Match the Debian release to its
records for [CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618)
and [CVE-2026-109619](https://security-tracker.debian.org/tracker/CVE-2026-109619).

| Debian release and PHP package | Fixed version | Advisory |
| --- | --- | --- |
| 12 (bookworm), `php8.2` | `8.2.35-1~deb12u1` | [DLA-4848-1](https://security-tracker.debian.org/tracker/DLA-4848-1) |
| 13 (trixie), `php8.4` | `8.4.27-1~deb13u1` | [DSA-6574-1](https://security-tracker.debian.org/tracker/DSA-6574-1) |

These are source package versions. Check the serving binary's package, such
as `php8.2-fpm` or `libapache2-mod-php8.2`, against the corresponding source.

### Ubuntu

Use `dpkg-query` to read the full installed package version and
`dpkg --compare-versions` for comparisons. Match the Ubuntu release and PHP
package to the advisory below.

| Ubuntu release and PHP package | Fixed version | Advisory |
| --- | --- | --- |
| 26.10, `php8.5` | `8.5.9-0ubuntu2.1` | [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) |
| 26.04 LTS, `php8.5` | `8.5.4-0ubuntu1.5` | [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) |
| 24.04 LTS, `php8.3` | `8.3.6-0ubuntu0.24.04.13` | [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) |
| 22.04 LTS, `php8.1` | `8.1.2-1ubuntu2.28` | [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) |
| 20.04 LTS, `php7.4` (Ubuntu Pro) | `7.4.3-4ubuntu2.29+esm5` | [USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2) |
| 18.04 LTS, `php7.2` (Ubuntu Pro) | `7.2.24-0ubuntu0.18.04.17+esm14` | [USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2) |
| 16.04 LTS, `php7.0` (Ubuntu Pro + Legacy Support) | `7.0.33-0ubuntu0.16.04.16+esm22` | [USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2) |
| 14.04 LTS, `php5` (Ubuntu Pro + Legacy Support) | `5.5.9+dfsg-1ubuntu4.29+esm18` | [USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2) |

Check the package serving the site, such as `php8.3-fpm` or
`libapache2-mod-php8.3`, rather than relying on the `php` metapackage.

### RHEL

Use `rpm -qf` on the serving binary or Apache module to identify its
owning package. Read its full version and vendor with:

```sh
rpm -q --queryformat '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH} %{VENDOR}\n' PACKAGE
```

Match the RHEL major/minor release and PHP module stream to the Red Hat
advisory. Use `dnf module list php --enabled` where module streams apply.
Known backports covering both CVEs include:

| RHEL release and PHP stream | Fixed version-release | Advisory |
| --- | --- | --- |
| RHEL 8.10, PHP 7.4 | `7.4.33-8.module+el8.10.0+25117+30337cca` | [RHSA-2026:87080](https://access.redhat.com/errata/RHSA-2026:87080) |
| RHEL 9.8, PHP 8.0 | `8.0.30-8.el9_8.1` | [RHSA-2026:87151](https://access.redhat.com/errata/RHSA-2026:87151) |

Use RPM version ordering, including the epoch, within the matching release
and stream. For other RHEL streams, consult Red Hat's records for
[CVE-2026-109618](https://access.redhat.com/security/cve/CVE-2026-109618) and
[CVE-2026-109619](https://access.redhat.com/security/cve/CVE-2026-109619).

### Upstream and other builds

For other providers, use their own advisories. Do not apply Debian, Ubuntu or
RHEL thresholds to another vendor's packages or custom builds.

The [upstream fixed releases](https://www.php.net/archive/2026.php#2026-10-21-5)
are 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Older branches may have vendor or source
backports.

## Verify the running site and report

A fixed installed package does not prove that web workers use it. Confirm the
serving installation and whether workers restarted after the update. If that
cannot be established, report the running site's patch status as unknown.

Report the package and version checked, the advisory and any required update.
Describe packages below the vendor fix as potentially vulnerable. If package
or build evidence is unavailable, or the provider or applicable advisory
cannot be established, report unknown.
