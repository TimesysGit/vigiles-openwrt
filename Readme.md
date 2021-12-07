![Timesys Vigiles](https://www.timesys.com/wp-content/uploads/vigiles-cve-monitoring.png "Timesys Vigiles")


Timesys Vigiles For OpenWrt
=============================

This is a collection of tools for image manifest generation used for security monitoring and notification as part of the **[Timesys Vigiles](https://www.timesys.com/security/vigiles/)** product offering.


What is Vigiles?
================

Vigiles is a vulnerability management tool that provides build-time CVE Analysis of OpenWrt target images. It does this by collecting metadata about packages to be installed and uploading it to be compared against the Timesys CVE database.A high-level overview of the detected vulnerabilities is returned and a full detailed analysis can be viewed online.


Register (free) and download the API key to access the full feature set based on Vigiles Basic, Plus or Prime:
https://linuxlink.timesys.com/docs/wiki/engineering/LinuxLink_Key_File


Using Vigiles CVE Check
=======================

To generate a vulnerability report follow the below steps: 


1. Clone vigiles-openwrt repository.

    ```sh
    git clone https://github.com/TimesysGit/vigiles-openwrt.git
    ```

2. Download your LinuxLink Key File here and store it at the (recommended) path.

    ```sh
    mkdir $HOME/timesys
    cp $HOME/Downloads/linuxlink_key $HOME/timesys/linuxlink_key
    ```

    > Note: If the key is stored elsewhere, the location can be specified via the Vigiles CVE Scanner (vigiles-openwrt.py) tool's command line argument (-K / --keyfile).

3. Run **Vigiles CVE Scanner** (vigiles-openwrt.py) with paths of **OpenWrt build directory** and a **Vigiles output directory** path (where generated report and manifest would be kept).
    ```sh
    cd {vigiles-openwrt clone directory}
    ./vigiles-openwrt.py -b {path of openwrt directory} -o {path of Vigiles output directory}
    ```

    > Example:
    > 
    >```./vigiles-openwrt.py -b /home/user/projects/openwrt -o /home/user/vigiles/output```
    >
    > Note: use **absolute paths** for openwrt and output directories.
    > 
    > Note: In case -o argument is not provided, the Vigiles CVE Scanner (vigiles-openwrt.py) would use **{PWD}/vigiles-output** as default **Vigiles output directory** .

4. View the Vigiles CVE (Text) Report Locally

    The CVE report will be located in the ```{Vigiles output directory}``` provided while running the Vigiles CVE Scanner (vigiles-openwrt.py) tool, with a name based on the board name; e.g.:
    ```sh
    wc -l vigiles/output/ath79-report.txt
        240 vigiles/output/ath79-report.txtt
    ```

5. View the Vigiles CVE Online Report

    The local CVE text report will contain a link to a comprehensive and graphical report; e.g.:
    ```
    -- Vigiles CVE Report --
            View detailed online report at:
              https://linuxlink.timesys.com/cves/reports/<Unique Report Identifier>
    ```

    #### The CVE Manifest
    The Vigiles CVE Scanner creates a manifest that it sends to the LinuxLink
    Server describing your build configuration. This manifest is located in the
    ```{Vigiles output directory}``` provided while running Vigiles CVE Scanner (vigiles-openwrt.py) 
    (the same location as the text report it receives back).
    ```sh
    wc -l vigiles/output/ath79-manifest.json 
        854 vigiles/output/ath79-manifest.json
    ```
    In the event that something goes wrong, or if the results seem incorrect,
    this file may offer insight as to why. It's important to include this file
    with any support request.

Configuration
=============

### Reporting and Filtering

Linux Kernel and U-Boot .config filtering can be enabled/disabled using the options
**```-k / --kernel-config```** and **```-u / --uboot-config```**.

If using a custom location for either the Kernel or U-Boot .config files, the
paths can be specified using **```-k / --kernel-config```** and
**```-u / --uboot-config```**.

The default for both paths is _```auto```_ which results in automatically using
the .config from the package's configured build directory. It is recommended
that this value is used unless it is absolutely necessary to specify an
alternative path.

In case you want to disable Linux Kernel and U-Boot .config filtering pass _```none```_
as argument value.

### Customizing / Amending the Vigiles Report

In some cases, it's desirable to modify the CVE report that Vigiles generates.
vigiles-openwrt supports the ability to _Include Additional Packages_,
_Exclude Packages_ and _Whitelist Known CVEs_. In addition, the file names of
the locally-generated Manifest and CVE Report may be customized.

All of these options are supported by a ```Vigiles CVE Scanner (vigiles-openwrt.py)``` argument where a user may
specify a CSV (comma-separated-value) file that describe the packages or CVEs.
Each is described below.


#### Manifest and Report Naming

By default, the file names of the Vigiles Manifest to be uploaded and the CVE
Report that is generated are given names based on the value of kconfig 
```CONFIG_TARGET_BOARD```, which will produce files like this:

```sh
output
├── ath79-manifest.json
└── ath79-report.txt
```


To use a custom name for the local Vigiles Manifest that is uploaded and the
CVE Report that is generated, the Vigiles CVE Scanner argument
```-N / --name```
can be used.

>Example:
> 
> ```-N Custom-Name```
> 
> Or
> 
> ```--name Custom-Name```

If set to '**Custom-Name**', the files produced will be:

```sh
output/vigiles
├── Custom-Name-manifest.json
└── Custom-Name-report.txt
```


#### Including Additional Packages

To include packages that are built outside the standard OpenWrt process
(and therefore wouldn't be included in the Vigiles CVE Report), the Vigiles CVE Scanner
argument ```-A / --additional-packages``` ("Additional Packages to Include
in Report") may be set to the path of a CSV file. 

>Example:
> 
> ```-A /home/user/vigiles-additional-packages.csv```
> 
> Or
> 
> ```--additional-packages /home/user/vigiles-additional-packages.csv```

The CSV file consists of an optional header and the following fields:

* Product - the CPE Name that packages use in CVEs
* (optional) Version - the version of the package used.
* (optional) License - the license of the package used

The following example shows the accepted syntax for expressing extra packages:

```sh
$ cat /home/user/vigiles-additional-packages.csv
product,version,license
avahi,0.6
bash,4.0
bash,4.1,GPL 3.0
busybox,
udev,,"GPLv2.0+, LGPL-2.1+"
```


#### Excluding Packages

In some cases, a more condensed CVE Report may be desired, so a list of
specific packages to omit may be specified (for example: packages that only
install data files).

To exclude packages from the CVE Report, the Vigiles CVE Scanner
argument ```-E / --exclude-packages``` may be set to the path of CSV file.

>Example:
> 
> ```-E /home/user/vigiles-exclude-packages.csv```
> 
> Or
> 
> ```--exclude-packages /home/user/vigiles-exclude-packages.csv```


The CSV file expects one package name per line. Any additional CSV fields are
ignored.

For example:

```sh
$ cat /home/user/vigiles-exclude-packages.csv
linux-libc-headers
opkg-utils
packagegroup-core-boot
```


#### Whitelisting CVEs

Some packages may have CVEs associated with them that are known to not affect
a particular machine or configuration.

A user may set the Vigiles CVE Scanner argument ```-W / --whitelist-cves``` to
the path of a CSV file containing a list of CVEs to omit from the Vigiles
Report.

>Example:
> 
> ```-W /home/user/vigiles-cve-whitelist.csv```
> 
> Or
> 
> ```--whitelist-cves /home/user/vigiles-cve-whitelist.csv```

The CSV expects one CVE ID per line. Any additional fields will be ignored.

For example:

```sh
$ cat /home/user/vigiles-cve-whitelist.csv
CVE-2021-37155
CVE-2018-12886
```

### Uploading the Manifest (Only)

In some cases, it may be desired to upload the Vigiles Manifest for a build
without generating a CVE Report.

This behavior can be enabled with the Vigiles CVE Scanner argument
```-U / --upload-only```.

Instead of a text report and a link to the online report, a link to the
Vigiles Dashboard Product Workspace (as specified with
VIGILES_DASHBOARD_CONFIG) will be displayed, from where it can be then be
scanned by the Vigiles Service.


### LinuxLink Credentials

To specify an alternative location for the Timesys LinuxLink Key File, (default: 
```$(HOME)/timesys/linuxlink_key```) it can be set with the Vigiles CVE Scanner argument
**```-K / --keyfile```**.

>Example:
> 
> ```-K /home/user/mylinuxlink_key```
> 
> Or
> 
> ```--keyfile /home/user/mylinuxlink_key```


>Whether the default is used, or if Vigiles CVE Scanner argument option is set, it will be
>overridden by the environment variable **VIGILES_KEY_FILE**.


### Vigiles Dashboard Configuration

A custom LinuxLink Dashboard configuration can be set by specifying the path in
the Vigiles CVE Scanner argument **```-C / --dashboard-config```**. If not provided, a default
path will be used (```$(HOME)/timesys/dashboard_config```)

>Example:
> 
> ```-C /home/user/mydashboard_config```
> 
> Or
> 
> ```--dashboard-config /home/user/mydashboard_config```


>Whether the default is used, or if Vigiles CVE Scanner argument option is set, it will be
>overridden by the environment variable **VIGILES_DASHBOARD_CONFIG**.


By default, your manifest will be uploaded to your "Private Workspace" Product
on the Vigiles Dashboard. This can be changed by downloading the "Dashboard
Config" for an alternative Product and/or Folder.

Dashboard Config files will be downloaded by default to e.g.
```"${HOME}/Downloads/dashboard_config"```. Once moving and/or renaming it as
necessary, you can control the behavior of Vigiles for openwrt by passing the dashboard config argument
as explained above.

>New Products can be defined by clicking on the "New Product" product link and specifying a name. To download the Dashboard Config for the top-level folder of that Product, click on the "Product Settings" link and then the "Download Dashboard Config" button.

>Once a new product is created, sub-folders may be created by clicking on the "Create Folder" and specifying a name. The Dashboard Config for that Folder (in that Product) may be downloaded by first clicking on/opening the Folder, then clicking the "Folder Settings" link and finally the "Download Dashboard Config" button.


### Dynamic subfolder creation
If a Dashboard Config is used, a subfolder name can be specified for dynamic folder creation by the Vigiles CVE 
Scanner argument **```-F / --subfolder```**.
Manifests will be uploaded to a subfolder with this name within the location specified in the Dashbord Config.
If one does not exist, it will be created. This option will be overridden by the environment variable ```VIGILES_SUBFOLDER_NAME```

>Example:
> 
> ```-F mysubfolder```
> 
> Or
> 
> ```--subfolder mysubfolder```


### Advanced Options

For development purposes, some "Expert" options are available.
These allow for debugging of the metadata that is collected.

These features are not supported and no documentation is provided for them.


#### Write Intermediate JSON Files of Collected Metadata

This behavior can be enabled with the Vigiles CVE Scanner argument
```-I, --write-intermediate```.


#### Debug messages

This behavior can be enabled with the Vigiles CVE Scanner argument
```-D, --enable-debug```.


Maintenance
===========

The Vigiles CVE Scanner and OpenWrt support are maintained by
[The Timesys Security team](mailto:vigiles@timesys.com).

For Updates, Support and More Information, please see:

[Vigiles Website](https://www.timesys.com/security/vigiles/)
