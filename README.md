# Humane Intel SGX Remote Attestation Framework for DCAP-RA (Humane-RAFW-DCAP)
(日本語での説明は後半にあります/Japanese version is below)
## Overview
This repository contains code and resources for an RA framework (RAFW) that enables Intel SGX DCAP-based Remote Attestation (hereinafter DCAP-RA) in its complete, officially intended form—where verification collateral is cached on a cache server called PCCS—at a “humane” level of difficulty that allows for easy implementation.

(*) This is also referred to as ECDSA-based RA (ECDSA-RA) and is the next-generation Remote Attestation scheme following the legacy EPID-based RA (EPID-RA).

Intel officially distributes [sample code](https://github.com/intel/confidential-computing.tee.dcap/tree/main/SampleCode), but compared to that, this repository has the following features:

* While the official DCAP-RA sample has been significantly improved compared to the official samples from the EPID-RA era, it still has shortcomings for server-side use of SGX Enclaves, such as managing quote generation and quote verification separately and having different Enclave definitions for each. This repository provides a convenient interface that allows Remote Attestation to be completed from start to finish by calling a single specific function only once, dramatically reducing the difficulty of implementing end-to-end RA.

* As with its predecessor [Humane-RAFW](https://github.com/acompany-develop/Humane-RAFW), which is an EPID-RA framework in the Humane-AFW series, this project eliminates obscure auto-generated components based on complex Automake setups or shell scripts. Developers can easily add new elements directly into Makefiles or the source code in a concise manner.

* Official information on how to build PCCS is scattered, making it difficult to set up. This repository provides detailed procedures to ensure PCCS operates correctly, enabling anyone to reproducibly build PCCS and use it for RA. The design works on both bare-metal SGX machines and Azure SGX servers, and compared to the Azure-specific [Humane-RAFW-MAA](https://github.com/acompany-develop/Humane-RAFW-MAA), it offers greater generality.

* For communication between the client (SP) and the SGX server (ISV), this project uses [cpp-httplib](https://github.com/yhirose/cpp-httplib). Data is Base64-encoded and exchanged in application/[json](https://github.com/nbsdx/SimpleJSON) format. This eliminates the need to rely on functions like msgio—which have performance and usability issues in the legacy EPID-RA official sample sgx-ra-sample—and allows user-defined communication to be implemented in a modern manner.

* RA-specific configuration information required by users (especially clients) is, in principle, fully handled through settings in settings.[ini](https://github.com/pulzed/mINI). For details, please refer to the explanations provided later in the documentation.

* As with EPID-RA, Elliptic Curve Diffie–Hellman key exchange for encrypted communication after successful RA is securely performed in parallel with RA, by signing concatenated public keys and embedding a hash of the concatenated public keys in the Report Data. The exchanged shared key can be used in exactly the same way as in Humane-RAFW. Since this functionality is not implemented at all in the official DCAP-RA sample, it greatly reduces the effort required to implement a secure communication channel.

* Management of RA sessions is also implemented, including an ID equivalent to `sgx_ra_context_t` (RA context) in EPID-RA and an associated internal management structure. This allows RA sessions to be specified and identified with exactly the same usage experience as EPID-RA.

* The source code includes explanatory comments where appropriate, addressing aspects that are often stumbling blocks when understanding or implementing RA. By referencing RA specifications from Intel and others alongside this code, it can also serve as an aid to understanding the RA mechanism itself.

* Auxiliary tools are provided to easily generate and obtain the data required for RA.

* By displaying the contents of Quotes and Supplemental Data with labels, it becomes easier to understand the actual state of the Enclave under verification. Additionally, the framework allows appraisal (specification and verification of expected values) of Quotes and Supplemental Data at a granularity that matches user requirements.

* Verification uses QvL and does not use QvE. This is because, except for special scenarios such as mutual RA between Enclaves, the trust-model benefits of using QvE are minimal, while it imposes the disadvantage of requiring SGX-capable machines on the verifier side. Therefore, the client-side code in this repository can run even on machines that do not support SGX.

## Installation
### Tested Environment
Operation has been verified on Azure, but the design allows it to run as-is on bare-metal SGX machines as well.
* OS: Ubuntu 24.04.3 LTS
* Azure instance: Standard DC4ds v3 (DCsv3/DCdsv3 series)
* Linux kernel: 6.14.0-1014-azure
* SGXSDK: Version 2.26
* DCAP library: Version 1.23
* OpenSSL: Version 3.0.13

Windows environments are not supported.  
For sections describing procedures performed on the Attester (SGX machine, server), use the section name [Attester]. For sections describing procedures performed on the Relying Party (RP; remote user, client) side, use the section name [RP]. This distinction need not be considered when all procedures are performed on the same machine.  

Furthermore, when the RP is provided separately, it shall also serve as the Verifier.

### Deploying Humane-RAFW-DCAP[Attester/RP]
Clone this repository into an arbitrary directory. In the following explanation, it is assumed that the repository is cloned under `~/Develop/sgx/`.

### Installing Linux-SGX[Attester]
Here, the installation procedure for Linux-SGX is explained in detail. If no explanation is required, please skip ahead to the next section.

* Install prerequisite packages for SGXSDK.
    ``` sh
    sudo apt-get -y install build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl
    ```

* Install prerequisite packages for SGXPSW.
    ``` sh
    sudo apt-get -y install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip pkgconf libboost-dev libboost-system-dev libboost-thread-dev lsb-release libsystemd0
    ```

* Clone the Linux-SGX (currently: confidential-computing.sgx) repository.
    ``` sh
    git clone https://github.com/intel/confidential-computing.sgx/tree/main
    ```

* Enter the directory and run the preparation binary.
    ``` sh
    cd linux-sgx && make preparation
    ```

* Build the SGXSDK.
    ``` sh
    make sdk
    ```

* Build the SGXSDK installer.
    ``` sh
    make sdk_install_pkg
    ```

* Install the SGXSDK.
    ``` sh
    pushd linux/installer/bin
    sudo ./sgx_linux_x64_sdk_${version}.bin
    ```
    In the case of Linux-SGX 2.26, the installer file name is `sgx_linux_x64_sdk_2.26.100.0.bin`.

    In this setup, the SDK is installed under `/opt/intel`. When prompted as follows, enter `no` and press Enter.
    ``` sh
    Do you want to install in current directory? [yes/no] : no
    ```

    Specify the installation path.
    ``` sh
    Please input the directory which you want to install in : /opt/intel
    ```

* Add the SGXSDK to the PATH. If you are building Enclave programs, this must be executed in each session if not already done.
    ``` sh
    source /opt/intel/sgxsdk/environment
    ```

* Build SGXPSW.
    ``` sh
    popd
    make psw
    ```

* Build the SGXPSW installer.
    ``` sh
    make deb_psw_pkg
    ```

* Build a local repository for installing SGXPSW.
    ``` sh
    make deb_local_repo
    ```

* To add the built local repository to `apt`, open `/etc/apt/sources.list` and append the following.
    ``` conf
    deb [trusted=yes arch=amd64] file:/PATH_TO_LOCAL_REPO noble main
    ```

    If `linux-sgx` is cloned under `/home/azureuser/Develop/sgx/`, it will look like this:
    ``` conf
    deb [trusted=yes arch=amd64] file://home/azureuser/Develop/sgx/linux-sgx/linux/installer/deb/sgx_debian_local_repo noble main
    ```

    If the following message appears when opening `/etc/apt/sources.list`,
    ```
    # Ubuntu sources have moved to the /etc/apt/sources.list.d/ubuntu.sources
    # file, which uses the deb822 format. Use deb822-formatted .sources files
    # to manage package sources in the /etc/apt/sources.list.d/ directory.
    # See the sources.list(5) manual page for details.
    ```
    then instead add the following to `/etc/apt/sources.list.d/ubuntu.sources`:
    ``` conf
    Types: deb
    URIs: file:/home/azureuser/Develop/sgx/linux-sgx/linux/installer/deb/sgx_debian_local_repo
    Suites: noble
    Components: main
    Architectures: amd64
    Trusted: yes
    Enabled: yes
    ```

* Update `apt` to reflect the added repository.
    ``` sh
    sudo apt update
    ```
    The following warnings may appear, but they can be safely ignored.
    ```
    N: Download is performed unsandboxed as root as file '/home/azureuser/Develop/sgx/linux-sgx/linux/installer/deb/sgx_debian_local_repo/dists/noble/InRelease' couldn't be accessed by user '_apt'. - pkgAcquire::Run (13: Permission denied)
    N: Missing Signed-By in the sources.list(5) entry for 'file:/home/azureuser/Develop/sgx/linux-sgx/linux/installer/deb/sgx_debian_local_repo'
    ```

* Execute the following commands to grant the current Linux user access permissions to SGX-related devices.
    ``` sh
    sudo usermod -aG sgx $USER
    sudo usermod -aG sgx_prv $USER
    ```

### Installing the DCAP Library[Attester/RP]
* Clone the DCAP library.
    ``` sh
    git clone --recursive https://github.com/intel/confidential-computing.tee.dcap
    ```
    The repository was previously named `SGXDataCenterAttestationPrimitives`, but it was renamed in the latter half of 2025.

* Install the required prerequisite packages.
    ``` sh
    sudo apt-get install build-essential wget python-is-python3 debhelper zip libcurl4-openssl-dev pkgconf libboost-dev libboost-system-dev libboost-thread-dev protobuf-c-compiler libprotobuf-c-dev protobuf-compiler
    ```

* Move to the source directory for the Quote generation libraries.
    ``` sh
    cd confidential-computing.tee.dcap/QuoteGeneration/
    ```

* Execute the shell script that downloads prebuilt packages.
    ``` sh
    ./download_prebuilt.sh
    ```

* If not already done in the current login session, add the SGXSDK to the PATH.
    ``` sh
    source /opt/intel/sgxsdk/environment
    ```

* Build and install the Quote generation–related libraries using the `make` command.
    ``` sh
    make
    ```

* Build the packages.
    ``` sh
    make deb_pkg
    ```

* Install prerequisite packages.
    ``` sh
    sudo apt install libsgx-headers
    ```

* Move to the directory where the generated deb packages are stored.
    ``` sh
    cd installer/linux/deb/
    ```

* As a precaution, install the development libraries.
    ``` sh
    sudo dpkg -i libsgx-dcap-ql-dev_*.deb
    sudo dpkg -i libsgx-dcap-ql-dbgsym_*.ddeb
    ```

* Install QPL (the library for fetching Quote collateral).
    ``` sh
    sudo dpkg -i libsgx-dcap-default-qpl_*.deb
    sudo dpkg -i libsgx-dcap-default-qpl-dev*.deb
    sudo dpkg -i libsgx-dcap-default-qpl-dbgsym*.ddeb
    ```

* Execute the following command to install the required libraries.
    ``` sh
    sudo apt install libsgx-enclave-common-dev libsgx-dcap-quote-verify-dev libsgx-dcap-default-qpl-dev
    ```

### Building PCCS[RP]
* By following the installation steps described above, `/etc/sgx_default_qcnl.conf` should already have been generated. As a precaution, back up this file to an appropriate location.
    ``` sh
    sudo cp -p /etc/sgx_default_qcnl.conf ~/Develop/sgx/
    ```

* Overwrite `/etc/sgx_default_qcnl.conf` with `sgx_default_qcnl.conf.pccs` bundled with this repository.
    ``` sh
    sudo cp sgx_default_qcnl.conf.pccs /etc/sgx_default_qcnl.conf
    ```
    As a precaution, also check the owner and permissions of `sgx_default_qcnl.conf`. In a verified environment, they are as follows:
    ``` sh
    -rw-r--r-- 1 root root 747 Dec  4 08:42 /etc/sgx_default_qcnl.conf
    ```

* Restart the aesmd service and confirm that it starts correctly.
    ``` sh
    sudo systemctl restart aesmd
    systemctl status aesmd
    ```

* Execute the following commands to install prerequisite packages for PCCS.
    ``` sh
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -yq --no-install-recommends nodejs=20.11.1-1nodesource1
    sudo apt-get install -y cracklib-runtime
    ```

* Install PCCS.
    ``` sh
    sudo apt install -y --no-install-recommends sgx-dcap-pccs
    ```

When executed, the installer will prompt for various inputs interactively. Enter values as shown below. In particular, be sure to select `LAZY` for the Caching Fill Method.
    ```
    Do you want to install PCCS now? (Y/N) :y
    Enter your http proxy server address, e.g. http://proxy-server:port (Press ENTER if there is no proxy server) :
    Enter your https proxy server address, e.g. http://proxy-server:port (Press ENTER if there is no proxy server) :

    Do you want to configure PCCS now? (Y/N) :y
    Set HTTPS listening port [8081] (1024-65535) :
    Set the PCCS service to accept local connections only? [Y] (Y/N) :n
    Set your Intel PCS API key (Press ENTER to skip) :<PCS_PRIMARY_KEY>
    Choose caching fill method : [LAZY] (LAZY/OFFLINE/REQ) :LAZY

    Set PCCS server administrator password:<enter an arbitrary PCCS administrator password>
    Re-enter administrator password:<re-enter the PCCS administrator password>
    Set PCCS server user password:<enter an arbitrary PCCS user password>
    Re-enter user password:<re-enter the PCCS user password>

    Do you want to generate insecure HTTPS key and cert for PCCS service? [Y] (Y/N) :y
    
    Country Name (2 letter code) [AU]:JA
    State or Province Name (full name) [Some-State]:Tokyo
    Locality Name (eg, city) []:shibuya
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:example co., ltd.
    Organizational Unit Name (eg, section) []: 
    Common Name (e.g. server FQDN or YOUR name) []:example.com
    Email Address []:user@example.com

    Please enter the following 'extra' attributes
    to be sent with your certificate request
    A challenge password []:
    An optional company name []:
    ```

#### Bare-metal Environment [Attester]
The procedures in this section apply **only when using a bare-metal environment, not Azure**.

* Install the PCK Cert ID Retrieval Tool (hereafter referred to as **PCKCIDRT**).
    ``` sh
    sudo apt install -y sgx-pck-id-retrieval-tool
    ```

* Run PCKCIDRT to obtain a CSV file that contains the Platform Manifest and related information.
    ``` sh
    cd /opt/intel/sgx-pck-id-retrieval-tool
    sudo ./PCKIDRetrievalTool -f host_$(hostnamectl --static).csv
    ```
    Once this CSV is obtained, it **cannot be retrieved again until an SGX Factory Reset is performed from the BIOS settings screen**. Therefore, handle this file with great care.

* Execute the following commands to extract the Platform Manifest from the CSV in binary format.
    ``` sh
    sudo apt-get install -y csvtool
    sudo bash -c "csvtool col 6 host_$(hostnamectl --static).csv | xxd -r -p > host_$(hostnamectl --static)_pm.bin"
    ```

* Send the extracted Platform Manifest binary to the IRS (Intel Registration Service) to register the platform.
    ``` sh
    curl -i \
    --data-binary @host_$(hostnamectl --static)_pm.bin \
    -X POST "https://api.trustedservices.intel.com/sgx/registration/v1/platform" \
    -H "Content-Type: application/octet-stream"
    ```

Bare-metal–specific operations end here.  
The following sections describe procedures that apply regardless of whether the environment is bare metal or Azure.  
Note that the steps diverge depending on whether the DCAP version is **1.24 or later**, or **1.23 or earlier**.

#### DCAP Version 1.24 or Later [Attester / RP]
* On the Attester, move to the PCS Client Tool directory within the official DCAP library.  
  Unless explicitly stated otherwise, the following steps are performed on the Attester.
    ``` sh
    cd confidential-computing.tee.dcap/tools/PcsClientTool/
    ```

* If using a bare-metal environment, copy the previously obtained CSV file.
    ``` sh
    cp /opt/intel/sgx-pck-id-retrieval-tool/host_$(hostnamectl --static).csv .
    ```

* Install pip3.
    ``` sh
    sudo apt install python3-pip
    ```

* Enable a virtual environment and install prerequisite packages.
    ``` sh
    sudo apt install python3-venv
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

* Using the PCS Client Tool, collect the platform list and then fetch collaterals for all FMSPCs.  
  After execution, exit the virtual environment using the `deactivate` command.
    ``` sh
    ./pcsclient.py collect -d . -o platform_list.json
    ./pcsclient.py fetch -p all -t early -o platform_collaterals.json
    deactivate
    ```
    When running the `fetch` command, you will be prompted as shown below.  
    Enter your PCS primary API key when requested.
    ```
    Please input ApiKey for Intel PCS:
    Would you like to remember Intel PCS ApiKey in OS keyring? (y/n)n
    ```

* If the RP and Attester are on separate machines, transfer `platform_collaterals.json` from the Attester to the RP using `scp` or a similar method.

* The following steps are performed on the RP.  
  Return to the working directory and clone the PCCS Admin Tool repository.
    ``` sh
    git clone --recursive https://github.com/intel/confidential-computing.tee.dcap.pccs.git
    ```

* Enter the cloned directory, then move into the `PccsAdminTool` directory and create a virtual environment.
    ``` sh
    cd confidential-computing.tee.dcap.pccs/PccsAdminTool
    python3 -m venv venv
    source venv/bin/activate
    ```

* Use the PCCS Admin Tool to register the collected collaterals with PCCS.
    ``` sh
    ./pccsadmin.py put -i platform_collaterals.json
    deactivate
    ```
    You will be prompted as follows.  
    Enter the PCCS administrator password you previously configured.
    ```
    Please input your administrator password for PCCS service:
    Would you like to remember password in OS keyring? (y/n)n
    ```

#### DCAP Version 1.23 or Earlier [Attester / RP]
* On the Attester, move to the directory containing the PCCS Admin Tool within the official DCAP library.  
  Unless explicitly stated otherwise, the following steps are performed on the Attester.
    ``` sh
    cd ~/Develop/sgx/confidential-computing.tee.dcap/tools/PccsAdminTool
    ```

* Install pip3.
    ``` sh
    sudo apt install python3-pip
    ```

* Enable a virtual environment and install prerequisite packages.
    ``` sh
    sudo apt install python3-venv
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

* Using the PCCS Admin Tool, collect the platform list and then fetch collaterals for all FMSPCs.
    ``` sh
    ./pccsadmin.py collect -d . -o platform_list.json
    ./pccsadmin.py fetch -p all -t early -o platform_collaterals.json
    ```
    When running the `fetch` command, you will be prompted as shown below.  
    Enter your PCS primary API key when requested.
    ```
    Please input ApiKey for Intel PCS:
    Would you like to remember Intel PCS ApiKey in OS keyring? (y/n)n
    ```

* If the RP and Attester are on separate machines, transfer `platform_collaterals.json` from the Attester to the RP using `scp` or a similar method.

* The following steps are performed on the RP.  
  Use the PCCS Admin Tool to load the previously obtained collateral list (`platform_collaterals.json`) into PCCS.
    ``` sh
    ./pccsadmin.py put -i platform_collaterals.json
    ```
    You will be prompted as follows.  
    Enter the PCCS administrator password you previously configured.
    ```
    Please input your administrator password for PCCS service:
    Would you like to remember password in OS keyring? (y/n)n
    ```

#### Continuation of Common Procedures for All Versions [RP / Attester]
* If the PCCS Caching Fill Method was not set to `LAZY` in the previous steps, open  
  `/opt/intel/sgx-dcap-pccs/config/default.json` and change the value of the `CachingFillMode` field to `LAZY`.

* To ensure that collaterals are being retrieved from **PCCS rather than PCS**, it is recommended to run Remote Attestation experiments with the following configuration:
    * Set the `collateral_service` field in `sgx_default_qcnl.conf` to the PCCS URL, i.e.  
      `https://localhost:8081/sgx/certification/v4/`
    * Completely delete the local cache directory, i.e. all contents under  
      `/home/azureuser/.dcap-qcnl/`

## Preparation
### Preparing CA Certificates for HTTPS Communication
By default, this repository includes CA certificates in the form of `ca-certificates.crt` within the repository directory (this file was taken directly from an Ubuntu 24.04 environment).

If you would like to prepare your own,
* On Ubuntu: `/etc/ssl/certs/ca-certificates.crt`
* On CentOS: `/etc/pki/tls/certs/ca-bundle.crt`

You can copy the file from one of these locations and name it `ca-certificates.crt`.

### Generating and Hardcoding the Client Signing Key Pair
In addition to the key pair for generating the shared secret that forms the basis of the RA session key (which is generated randomly at runtime), a 256-bit ECDSA key pair is required. This key pair is used by the client to sign the concatenation of both parties’ public keys, and by the SGX server to verify that signature.

For this key pair, the public key must be hardcoded into the SGX server’s Enclave code (`Server_Enclave/server_enclave.cpp`), and the private key must be hardcoded into the client code (`Client_App/client_app.cpp`). To prevent tampering, hardcoding the public key into the Enclave code is especially critical.

By default, a randomly generated key pair has already been hardcoded, so RA can be executed without any changes. However, if you wish to use your own key pair, you can use the bundled auxiliary tool `client-ecdsa-keygen`.

This tool generates an ECDSA key pair and outputs it to standard output in a source-code-like format, allowing you to easily hardcode the keys by copy and paste.

The procedure for generating and hardcoding a key pair using this tool is described below:

* Move to the path where `client-ecdsa-keygen` is located.
    ```
    cd subtools/client-ecdsa-keygen/
    ```

* Build it using the `make` command.
    ```
    make
    ```

* Execute the binary generated by the build.
    ```
    ./keygen
    ```

* Output similar to the following will be printed to standard output.
    ```
    (snip)
    Copy the following public keys and hardcode them into Server's Enclave code (ex: server_enclave.cpp):

        {
                0xb5, 0x72, 0x2f, 0xb9, 0x04, 0x2d, 0xcd, 0xd9,
                0x73, 0x63, 0x42, 0x4b, 0xe2, 0xda, 0xb8, 0x7c,
                0x58, 0xf6, 0x5c, 0x5d, 0x58, 0xe8, 0x71, 0xda,
                0x69, 0x12, 0x33, 0x5b, 0x9b, 0xee, 0x73, 0x80
        },
        {
                0xef, 0x69, 0x4d, 0x3c, 0x92, 0x99, 0xae, 0x25,
                0xf4, 0x7c, 0xb8, 0x36, 0xad, 0x11, 0x47, 0x27,
                0xfa, 0x0c, 0x7d, 0xd1, 0x5d, 0x6a, 0x08, 0xd7,
                0xff, 0x01, 0x41, 0xda, 0x72, 0x19, 0xc7, 0x7f
        }



    Copy the following private key and hardcode it into Client's untrusted code (ex: client_app.cpp):

            0x1e, 0xe0, 0x50, 0x82, 0x08, 0x57, 0x91, 0x17,
            0xa9, 0xe8, 0x51, 0x27, 0x5f, 0xf5, 0x19, 0xec,
            0xe7, 0xa9, 0x83, 0x80, 0x8d, 0xd8, 0xbc, 0x3b,
            0x5c, 0xdb, 0x2c, 0x64, 0x2a, 0x33, 0xde, 0xd6
    ```

* From the above output, copy and paste the public keys (the upper two blocks) into the `static const sgx_ec256_public_t client_signature_public_key` variable in `Server_Enclave/client_pubkey.hpp`, as shown below.
    ``` cpp
    static const sgx_ec256_public_t client_signature_public_key[2] = {
        {
            // These values correspond to the default key in client_app.cpp.
            {
                0xb0, 0x81, 0x99, 0x7f, 0xac, 0xe4, 0xdd, 0x8a,
                0x38, 0x72, 0x71, 0x3b, 0xb7, 0xce, 0xe0, 0xcb,
                0xe3, 0xed, 0xaa, 0xe1, 0x9d, 0x60, 0x10, 0x55,
                0x59, 0x2c, 0x4f, 0x36, 0x4f, 0xe5, 0x18, 0x35
            },
            {
                0x33, 0x89, 0xd3, 0x07, 0x14, 0x3d, 0x2e, 0x2d,
                0x1f, 0x70, 0x69, 0x33, 0x9b, 0x27, 0x9a, 0x73,
                0x7f, 0x6d, 0x71, 0x76, 0x55, 0x83, 0xfa, 0x0a,
                0x81, 0xc8, 0x3e, 0x84, 0xac, 0x36, 0xbf, 0xad
            }
        },
        {
            // This is a dummy placeholder for a second client.
            // Replace it when actually using it. Add more entries manually for additional clients.
            {
                0xb7, 0x6a, 0xce, 0x37, 0x02, 0x20, 0xeb, 0x93,
                0xd2, 0xf8, 0xb6, 0xdc, 0xa0, 0x3d, 0x44, 0xcf,
                0xd0, 0x40, 0xaf, 0x93, 0x75, 0x77, 0x66, 0x27,
                0xf9, 0xad, 0x40, 0xf3, 0xe5, 0x9b, 0xd0, 0xc3
            },
            {
                0x6c, 0x47, 0xe7, 0x78, 0xe3, 0xac, 0x5e, 0x1f,
                0xe6, 0x9a, 0xfe, 0xdc, 0x86, 0x5b, 0x34, 0xbc,
                0x92, 0xb0, 0x1f, 0x94, 0xb5, 0x43, 0xfb, 0x7e,
                0x9a, 0xf2, 0x54, 0x9f, 0xc2, 0x0b, 0x6c, 0x2c
            }
        }
    };
    ```
    Since this public-key storage variable for signature verification is an array of type `sgx_ec256_public_t`, you can handle multiple clients by manually adding entries equal to the number of clients.

* Similarly, copy and paste the private key (the final block) into the `static const uint8_t g_client_signature_private_key[32]` variable in `Client_App/client_app.cpp`, as shown below.
    ``` cpp
    static const uint8_t g_client_signature_private_key[32] = {
        0xef, 0x5c, 0x38, 0xb7, 0x6d, 0x4e, 0xed, 0xce,
        0xde, 0x3b, 0x77, 0x2d, 0x1b, 0x8d, 0xa7, 0xb9,
        0xef, 0xdd, 0x60, 0xd1, 0x22, 0x50, 0xcc, 0x90,
        0xc3, 0xb5, 0x17, 0x54, 0xdc, 0x2f, 0xe5, 0x18
    };
    ```

### Configuring the Enclave Signing Key
The key used for signing the Enclave is stored by default as `Server_Enclave/private_key.pem`, and this file is used as-is.

However, for production use, it is recommended to generate and use your own key. Please generate a new key using the following command and store it at the above path with the same file name.

``` bash
openssl genrsa -out private_key.pem -3 3072
```

### Communication Settings
By default, both the client and the SGX server are assumed to be deployed on the same machine and configured to communicate with each other via localhost on port 1234.

If you want to change these communication settings, edit the following locations on the client and SGX server respectively.

* For the client: edit the following line in `Client_App/client_app.cpp`.
    ``` cpp
    std::string server_url = "http://localhost:1234";
    ```
    Example:
    ``` cpp
    std::string server_url = "http://example.com:1234";
    ```

* For the SGX server: edit the following line in `Server_App/server_app.cpp`.
    ``` cpp
    svr.listen("localhost", 1234);
    ```
    Example:
    ``` cpp
    svr.listen("0.0.0.0", 1234);
    ```
    By default, `"localhost"` is specified explicitly to indicate local-only operation, but in most cases `"0.0.0.0"` should work without issue. For more details, please refer to the [cpp-httplib repository](https://github.com/yhirose/cpp-httplib).

## Build, Configuration, and Execution
### Build
Once preparation is complete, move to the root directory of Humane-RAFW-DCAP and execute the build using the `make` command.

``` bash
make
```


If build logs like the following are displayed, the build has completed successfully.
```
user@machine:~/Develop/sgx/Humane-RAFW-DCAP$ make
GEN  =>  Server_App/server_enclave_u.c
CC   <=  Server_App/server_enclave_u.c
CXX  <=  Server_App/server_app.cpp
CXX  <=  common/error_print.cpp
CXX  <=  common/base64.cpp
CXX  <=  common/debug_print.cpp
CXX  <=  common/hexutil.cpp
CXX  <=  common/crypto.cpp
LINK =>  server_app
GEN  =>  Server_Enclave/server_enclave_t.c
CC   <=  Server_Enclave/server_enclave_t.c
CXX  <=  Server_Enclave/server_enclave.cpp
/usr/bin/ld: warning: memmove.o: missing .note.GNU-stack section implies executable stack
/usr/bin/ld: NOTE: This behaviour is deprecated and will be removed in a future version of the linker
LINK =>  enclave.so
<!-- Please refer to User's Guide for the explanation of each field -->
<EnclaveConfiguration>
    <ProdID>0</ProdID>
    <ISVSVN>0</ISVSVN>
    <StackMaxSize>0x40000</StackMaxSize>
    <HeapMaxSize>0x5000000</HeapMaxSize>
    <TCSNum>10</TCSNum>
    <TCSPolicy>1</TCSPolicy>
    <DisableDebug>1</DisableDebug>
    <MiscSelect>0</MiscSelect>
    <MiscMask>0xFFFFFFFF</MiscMask>
    <EnableKSS>1</EnableKSS>
    <ISVEXTPRODID_H>1</ISVEXTPRODID_H>
    <ISVEXTPRODID_L>2</ISVEXTPRODID_L>
    <ISVFAMILYID_H>3</ISVFAMILYID_H>
    <ISVFAMILYID_L>4</ISVFAMILYID_L>
</EnclaveConfiguration>
tcs_num 10, tcs_max_num 10, tcs_min_pool 1
INFO: Enclave configuration 'MiscSelect' and 'MiscSelectMask' will prevent enclave from using dynamic features. To use the dynamic features on SGX2 platform, suggest to set MiscMask[0]=0 and MiscSelect[0]=1.
The required memory is 89649152B.
The required memory is 0x557f000, 87548 KB.
Succeed.
writing RSA key
<!-- Please refer to User's Guide for the explanation of each field -->
<EnclaveConfiguration>
    <ProdID>0</ProdID>
    <ISVSVN>0</ISVSVN>
    <StackMaxSize>0x40000</StackMaxSize>
    <HeapMaxSize>0x5000000</HeapMaxSize>
    <TCSNum>10</TCSNum>
    <TCSPolicy>1</TCSPolicy>
    <DisableDebug>1</DisableDebug>
    <MiscSelect>0</MiscSelect>
    <MiscMask>0xFFFFFFFF</MiscMask>
    <EnableKSS>1</EnableKSS>
    <ISVEXTPRODID_H>1</ISVEXTPRODID_H>
    <ISVEXTPRODID_L>2</ISVEXTPRODID_L>
    <ISVFAMILYID_H>3</ISVFAMILYID_H>
    <ISVFAMILYID_L>4</ISVFAMILYID_L>
</EnclaveConfiguration>
tcs_num 10, tcs_max_num 10, tcs_min_pool 1
INFO: Enclave configuration 'MiscSelect' and 'MiscSelectMask' will prevent enclave from using dynamic features. To use the dynamic features on SGX2 platform, suggest to set MiscMask[0]=0 and MiscSelect[0]=1.
The required memory is 89649152B.
The required memory is 0x557f000, 87548 KB.
handle_compatible_metadata: Overwrite with metadata version 0x100000005
Succeed.
SIGN (two-step) =>  enclave.signed.so
CXX  <=  Client_App/client_app.cpp
CXX  <=  common/jwt_util.cpp
LINK =>  client_app
```

## Build, Configuration, and Execution
### Configuration
Before execution, describe the configuration information used by the client for RA in `settings_client.ini`.  
**By default, the file is named `settings_client_template.ini`, so be sure to rename it to `settings_client.ini` before using it.**

Below is a list of explanations for each required configuration item (key) in `settings_client.ini` (double quotation marks are not required for any values):

| Setting Item | Description | Recommended Value |
| -- | -- | -- |
| CLIENT_ID | Specifies the client ID. This value corresponds to the index of `client_signature_public_key`, the array of signature-verification public keys hardcoded in `Server_Enclave/client_pubkey.hpp`, as registered in the “Preparation” section. When operating with a single client only, this can always be 0. | - |
| MINIMUM_ISVSVN | The minimum ISVSVN value required by the client for the SGX server. ISVSVN is configured on the SGX server side via the `<ISVSVN>` tag in `Server_Enclave/Enclave.config.xml`. | Greater than or equal to the value set in the Enclave configuration file |
| REQUIRED_ISV_PROD_ID | The ISV Product ID value required by the client for the SGX server. The ISV Product ID is configured on the SGX server side via the `<ProdID>` tag in `Server_Enclave/Enclave.config.xml`. | The value set in the Enclave configuration file |
| REQUIRED_MRENCLAVE | The MRENCLAVE value required for the SGX server. The client records the expected MRENCLAVE of the Enclave in advance (= the value set here) and compares it against the MRENCLAVE contained in the Quote structure received from the SGX server during RA. The method for obtaining this value is described later. | The expected MRENCLAVE value of the Enclave |
| REQUIRED_MRSIGNER | The MRSIGNER value required for the SGX server. The client records the expected MRSIGNER of the Enclave in advance (= the value set here) and compares it against the MRSIGNER contained in the Quote structure received from the SGX server during RA. The method for obtaining this value is described later. | The expected MRSIGNER value of the Enclave |
| SKIP_MRENCLAVE_CHECK | If set to 1, verification of MRENCLAVE is skipped during RA. Since MRENCLAVE changes whenever the Enclave code changes, this can be cumbersome during development, and this option allows temporarily skipping the check for convenience. **Be sure to set this to 0 in production.** | 0 |
| ALLOW_SW_HARDENING_NEEDED | Whether to accept RA even if the RA status includes `SW_HARDENING_NEEDED`. 0 rejects, 1 allows. If the RA status includes multiple flags (e.g., `TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED`), the corresponding settings must also be set to 1, otherwise RA will not be accepted. | Basically 0, but 1 if updates are not possible (e.g., when using Azure) |
| ALLOW_CONFIGURATION_NEEDED | Whether to accept RA even if the RA status includes `CONFIGURATION_NEEDED`. 0 rejects, 1 allows. If the RA status includes multiple flags (e.g., `TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED`), the corresponding settings must also be set to 1, otherwise RA will not be accepted. | Same as above |
| ALLOW_OUT_OF_DATE | Whether to accept RA even if the RA status includes `OUT_OF_DATE`. 0 rejects, 1 allows. If the RA status includes multiple flags (e.g., `TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED`), the corresponding settings must also be set to 1, otherwise RA will not be accepted. | Same as above |
| ALLOW_DEBUG_ENCLAVE | Whether to allow Debug-mode Enclaves. 0 rejects, 1 allows. **Be sure to set this to 0 in production.** | 0 |
| ALLOW_COLLATERAL_EXPIRATION | Whether to allow expired collateral. 0 rejects, 1 allows. | 0 if collateral can be kept up to date; 1 if difficult, such as on Azure |
| ALLOW_SMT_ENABLED | Whether to allow hyper-threading enabled on the machine hosting the Enclave. 0 rejects, 1 allows. | In principle 0, since hyper-threading can facilitate various attacks |
| ALLOWED_SA_LIST | A list of allowed security advisories (SA). When specifying multiple entries, list them separated by commas. Always use the format INTEL-SA-XXXXX, where the numeric part must be 5 digits (e.g., `ALLOWED_SA_LIST = INTEL-SA-00086, INTEL-SA-00615, INTEL-SA-01153`). To allow all security advisories unconditionally, specify only `ALL`. To allow none at all, specify only `none`. | Ideally `none`, but depending on vulnerability details and risk, specify (allow) the minimum necessary |

Next, below is a list of explanations for each optional configuration item in the same file (double quotation marks are not required for any values):

| Setting Item | Description | Recommended Value |
| -- | -- | -- |
| MINIMUM_TCB_EVAL_DATASET_NUM | The minimum acceptable TCB Evaluation Dataset Number. Specify as an integer. If not required, specify 0. | Decide based on the number shown after “TCB-R Counter:” in the table on [this page](https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/trusted-computing-base-recovery-attestation.html) and the contents of that column. Ideally, use the latest value at the time (20 as of 2025/12/19). |
| REQUIRED_ISV_EXT_PROD_ID_HIGHER | The upper 8 bytes of the expected ISV Extended Product ID. Specify in decimal. If not required, specify `none` (in which case LOWER must also be `none`). | The value set in the Enclave configuration file; `none` if this KSS value is not used |
| REQUIRED_ISV_EXT_PROD_ID_LOWER | The lower 8 bytes of the expected ISV Extended Product ID. Specify in decimal. If not required, specify `none` (in which case HIGHER must also be `none`). | The value set in the Enclave configuration file; `none` if this KSS value is not used |
| REQUIRED_ISV_FAMILY_ID_HIGHER | The upper 8 bytes of the expected ISV Family ID. Specify in decimal. If not required, specify `none` (in which case LOWER must also be `none`). | The value set in the Enclave configuration file; `none` if this KSS value is not used |
| REQUIRED_ISV_FAMILY_ID_LOWER | The lower 8 bytes of the expected ISV Family ID. Specify in decimal. If not required, specify `none` (in which case HIGHER must also be `none`). | The value set in the Enclave configuration file; `none` if this KSS value is not used |
| REQUIRED_CONFIG_ID | The expected Config ID value. Specify as a 128-character hexadecimal string (64 bytes in binary). If not required, specify `none`. | The Config ID value passed to `sgx_create_enclave_ex()` in `server_app.cpp` |
| MINIMUM_CONFIG_SVN | The minimum acceptable Config SVN. Specify as an integer (`uint16_t`). If not required, specify 0. | Greater than or equal to the Config SVN value passed to `sgx_create_enclave_ex()` in `server_app.cpp` |
| MINIMUM_PCE_SVN | The minimum acceptable PCE SVN. Specify as an integer (`uint16_t`). If not required, specify 0. | Not specified by default. If you want to specify it, first perform RA with this repository in an environment where the correct PCE is certainly in use, and then set the value printed to standard output |
| MINIMUM_QE_SVN | The minimum acceptable QE3 SVN. Specify as an integer (`uint16_t`). If not required, specify 0. | Same as above |
| REQUIRED_QE_PROD_ID | The expected Prod ID of the QE3 to be used. Specify as an integer (`uint16_t`). If not required, specify `none`. | Same as above |
| REQUIRED_QE_MRENCLAVE | The expected MRENCLAVE of the QE3 to be used. Specify as a 64-character hexadecimal string (32 bytes in binary). If not required, specify `none`. | Same as above |
| REQUIRED_QE_MRSIGNER | The expected MRSIGNER of the QE3 to be used. Specify as a 64-character hexadecimal string (32 bytes in binary). If not required, specify `none`. | Same as above |

The MRENCLAVE and MRSIGNER values specified in `REQUIRED_MRENCLAVE` and `REQUIRED_MRSIGNER` above can be easily extracted from a signed Enclave image by using the auxiliary tool `mr-extract`.

Below is an explanation of how to extract each value using this tool:

* Build the Humane-RAFW-DCAP main project and confirm that the signed Enclave image has been built and exists.
    ``` bash
    user@machine:~/Develop/sgx/Humane-RAFW-DCAP$ ls -l enclave.signed.so 
    -rw-rw-r-- 1 user user 3295136 Dec 19 07:45 enclave.signed.so
    user@machine:~/Develop/sgx/Humane-RAFW-DCAP$
    ```

* Move to the path where `mr-extract` is located.
    ```
    cd subtools/mr-extract/
    ```

* Build it using the `make` command.
    ```
    make
    ```

* Execute the binary generated by the build.
    ```
    ./mr-extract
    ```
    If the SGXSDK path is not `/opt/intel/sgxsdk/`, or if the signed Enclave image name is not located at `../../enclave.signed.so` when viewed from the `mr-extract` directory, you can specify the locations using the `-t` and `-e` options as shown below.
    ```
    ./mr-extract -t <SGXSDK_PATH> -e <ENCLAVE_PATH>
    ```

* Output similar to the following will be printed to standard output.
    ```
    -------- message from sgx_sign tool --------
    Succeed.
    --------------------------------------------

    Copy and paste following measurement values into settings.ini.
    MRENCLAVE value -> c499d7bf5c0f9fe6f7cee583e3fdaca722faa9507c17b6e317a386e0f6eeb194
    MRSIGNER value  -> babdf7eb81e8f91f1d14fa70200f76c4b49b85a3caf591faa3761d3b5910a9d5
    ```
    In this example, set `c499d7bf5c0f9fe6f7cee583e3fdaca722faa9507c17b6e317a386e0f6eeb194` as `REQUIRED_MRENCLAVE`, and `babdf7eb81e8f91f1d14fa70200f76c4b49b85a3caf591faa3761d3b5910a9d5` as `REQUIRED_MRSIGNER`.

### Execution
Once the build and configuration are complete, first start the SGX server using the following command:
```
./server_app
```

After the SGX server has started, run the client application with the following command:
```
./client_app
```

RA will then be executed. If RA is accepted, the client encrypts secret information using the RA session key and sends it to the SGX server. The SGX server adds the secret values together inside the Enclave, encrypts the result, and returns it to the client. This demonstrates a very simple example of confidential computation.


## Applying This Framework
### Cryptographic Functions
The functions `aes_128_gcm_encrypt()`, `aes_128_gcm_decrypt()`, and `generate_nonce()`, which are also used in the sample confidential computation function (`sample_remote_computation()`), can be used for encryption and decryption using the RA session key, as well as for random generation of initialization vectors and similar values.

### Data Formats for Communication
For data communication between the client and the SGX server, each value is Base64-encoded and exchanged by storing them in JSON format.

### Complete Separation of RA Framework Code
By default, the client defines its `main` function (which calls the RA execution function) in `Client_App/client_app.cpp`, and the SGX server defines its `main` function in `Server_App/server_app.cpp`.  
If you want to completely separate the RA portion from your own code files, define the `main` function and related logic in your own source files and modify the Makefile accordingly.

For example, if you add a new file `Client_App/my_program.cpp` and declare the `main` function there to invoke RA, add the source file to the following section:
``` makefile
## List C/C++ source files used during compilation
Client_Cpp_Files := Client_App/client_app.cpp common/base64.cpp common/debug_print.cpp common/hexutil.cpp \
				common/crypto.cpp
```

as shown below:
``` makefile
## List C/C++ source files used during compilation
Client_Cpp_Files := Client_App/client_app.cpp common/base64.cpp common/debug_print.cpp common/hexutil.cpp \
				common/crypto.cpp Client_App/my_program.cpp
```

### Supporting Multiple Clients
By default, the framework is configured to support a single client communicating with a single SGX server, but it can be modified to support multiple clients.

The SGX server already identifies RA sessions using RA context values, and the client implementation also retains the RA context value and passes it to the SGX server as needed.

Therefore, by implementing client identification logic at the untrusted-layer level and properly managing the hardcoded client signature verification public keys in the Enclave code, it is possible to extend the framework to support multiple clients.


## External Libraries Used
All of the following are header-only libraries and are already included in the repository (under the `include/` directory).
* [cpp-httplib](https://github.com/yhirose/cpp-httplib): MIT License
* [SimpleJSON](https://github.com/nbsdx/SimpleJSON): WTFPL License
* [mINI](https://github.com/pulzed/mINI): MIT License


## Other Specifications and Notes
### AE Operation Modes
In DCAP-RA Quote generation, there are two modes for running AEs (Architectural Enclaves) such as the PCE (Platform Certification Enclave) and QE3 (Quoting Enclave for 3rd party attestation), along with related services: a mode in which they run within the Quote generation process, and a mode in which they run outside the process.

The former, where they run inside the process, is called In-Proc mode, while the latter, where they are handled by an external daemon (AESM), is called Out-of-Proc mode.  
(Reference: https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-aks-addon)

On Azure DCsv3 machines, only the Out-of-Proc mode is basically supported, and switching to In-Proc mode has not been successful in the author’s environment.

Therefore, taking Azure compatibility into account, Humane-RAFW-DCAP is implemented on the assumption that Out-of-Proc mode is used.

Occasionally, the background service required for Out-of-Proc mode may be down at the time the SGX server attempts to generate a Quote. In such cases, the implementation is designed to terminate abnormally because a Quote cannot be generated. However, based on experience, the service usually recovers and functions normally after waiting a few minutes.

### QPL Configuration JSON File
The QPL configuration file `sgx_default_qcnl.conf`, which is placed under `/etc/`, is in JSON format. If there is even a small error in the JSON formatting, QPL will fail to fetch collateral, resulting in the generation of an incomplete Quote.

Using such an incomplete Quote will lead to errors. Therefore, be very careful to avoid introducing JSON formatting errors—for example, by copying and pasting the configuration file bundled with this repository as-is.

### Enclave Mode
In the legacy EPID-RA scheme, the IAS API for production Enclave RA could not be used without obtaining a license from Intel. As a result, Humane-RAFW assumed operation in debug mode by default.

However, DCAP-RA does not have such restrictions, so Enclaves are built in production mode and RA is executed accordingly.

As a result, Enclave signing is performed using a two-step signing process rather than a single-step signing process. All steps of the two-step signing process are automated via `make`, but if you prefer signing in a strictly controlled environment or on dedicated devices (such as an HSM), you can modify the Makefile as appropriate and offload the signing process.

## License
The contents of this repository are developed by the same author based on [Humane-RAFW-MAA](https://github.com/acompany-develop/Humane-RAFW-MAA/).  
For reused or modified components derived from Humane-RAFW-MAA, the MIT License of Humane-RAFW-MAA is inherited.  
All newly added content in this repository is also released under the MIT License.

## Acknowledgment
This work is supported by JST K Program Grant Number JPMJKP24U4, Japan.

---

(日本語版)
## 概要
本リポジトリは、Intel SGXにおけるDCAP方式(*)のRemote Attestation（以下、DCAP-RA）を、検証用付属情報（コラテラル）をPCCSというキャッシュサーバにキャッシュさせる公式想定の完全な形で、「人道的な（Humane）」難易度で手軽に実現する事ができる、RAフレームワーク（RAFW）のコードやリソースを格納しています。

(*)ECDSA方式のRA（ECDSA-RA）としても言及されるもので、旧来のEPID方式のRA（EPID-RA）の次世代に位置する方式のRemote Attestationです。  

Intel公式にも[サンプルコード](https://github.com/intel/confidential-computing.tee.dcap/tree/main/SampleCode)が配布されていますが、そちらと比較して以下のような特長があります。
* 公式DCAP-RAサンプルは、EPID-RA時代の公式サンプルよりは大分改善されていますが、それでもQuote生成とQuote検証で別々の管理となっている、これら両者でEnclaveの定義が違う等、SGX Enclaveをサーバ利用する上ではまだ不足する部分があります。本リポジトリでは、特定の単一の関数を1度のみ呼び出すだけでRAを最初から最後まで完遂させる事の出来る、便利なインタフェースを提供しており、E2EでのRA実装の難易度が劇的に改善されます。

* Humane-AFWシリーズにおけるEPID-RA用フレームワークである先代の[Humane-RAFW](https://github.com/acompany-develop/Humane-RAFW)同様、複雑なAutomakeやシェルスクリプトによる難解な自動生成要素を排しており、開発者は新たに加えたい要素をMakefileやコード中に簡潔に加える事が出来ます。

* 構築方法に関する公式情報が散逸しており、構築難易度が高いPCCSについて、正常に動作させるための手順を詳細に掲載し、誰でも再現性を持ってPCCSを構築しRAに利用できるようにしています。また、少なくともベアメタルSGXマシンとAzure SGXサーバの双方で動作する設計となっており、Azureに特化した[Humane-RAFW-MAA](https://github.com/acompany-develop/Humane-RAFW-MAA)と比較しても、より汎用性が増しています。

* クライアント（SP）とSGXサーバ（ISV）との通信には[cpp-httplib](https://github.com/yhirose/cpp-httplib)を採用しており、データの送受信時にはBase64コーディングをかけ、application/[json](https://github.com/nbsdx/SimpleJSON)形式で送受信を行います。これにより、旧EPID-RAの公式サンプルであるsgx-ra-sampleにおける、性能面及びユーザビリティ面で難があるmsgioのような関数に頼る必要なく、ユーザ定義の通信の実装時も近代的な方法で行う事が出来ます。

* ユーザ（特にクライアント）によって必要な、RA特有の設定情報は、原則としてsettings.[ini](https://github.com/pulzed/mINI)内における設定で完結出来る設計になっています。詳細については後述の各種説明を参照してください。

* EPID-RA同様、公開鍵の連結に対して署名を打ったり、Report Dataに公開鍵の連結に対するハッシュ値を同梱したりしながら、RA成立後の暗号通信のための楕円曲線ディフィー・ヘルマン鍵共有をRAに並行して安全に実施します。交換した共通鍵は、Humane-RAFWと全く同じ方法で利用する事ができます。これは、公式DCAP-RAサンプルにおいては一切実装されていない機能であるため、暗号通信路確立の実装の手間が大幅に省けます。

* EPID-RAにおける `sgx_ra_context_t`（RAコンテキスト）相当のID及び、それに紐づく内部の管理用構造体によるRAセッションの管理も実装しております。これにより、EPID-RAと全く同じ使用感でRAセッションの指定や識別を行う事ができます。

* ソースコード内には適宜コメントで解説を加えており、RAの仕組みを理解したり実装する上で躓きがちな部分の解説を行っております。このコードと照らし合わせながらIntel等によるRAの仕様書を参照する事で、RAの理解の一助にもなるかと思われます。

* RAにおいて用意する必要のあるデータを簡単に生成・取得できる、補助用のツールを用意しています。

* Quote及び補足情報（Supplemental Data）について、その中身をラベル付きで表示する事で、検証対象Enclaveの実態をより把握しやすくなっています。また、ユーザの希望に合わせた粒度でQuoteやSupplemental DataのAppraisal（期待する値の指定・検証）を行えるようにしています。

* 検証にはQvLを使用し、QvEは使用しません。これは、Enclave間相互RAのような特殊なシナリオを除き、QvEを使用する事による信頼モデル上のメリットが薄く、寧ろ検証側にもSGX対応マシンを要求する制約となりデメリットの方が大きいためです。よって、本リポジトリのクライアント側コードは、SGX対応マシンでなくとも動作させる事ができます。


## 導入
### 動作確認環境
Azureでの動作確認を行っていますが、ベアメタルSGXマシンでもそのまま動作する設計となっています。
* OS: Ubuntu 24.04.3 LTS
* Azureインスタンス: Standard DC4ds v3（DCsv3/DCdsv3シリーズ）
* Linuxカーネル: 6.14.0-1014-azure
* SGXSDK: バージョン2.26
* DCAPライブラリ: バージョン1.23
* OpenSSL: バージョン3.0.13

Windows環境には対応していません。  
Attester（SGXマシン、サーバ）で行う手順のセクション名には[Attester]を、Relying Party（RP; リモートユーザ、クライアント）側で行う手順のセクション名には[RP]を付与します。全て同一マシン上で実施する場合には意識する必要はありません。  
また、RPを別途用意する場合、RPがVerifierも兼ねるものとします。

### Humane-RAFW-DCAPの展開[Attester/RP]
任意のディレクトリにて、本リポジトリをクローンしてください。以下では、`~/Develop/sgx/`配下にクローンする前提で説明を進めます。

### Linux-SGXのインストール[Attester]
ここでは、Linux-SGXについてもインストール手順を詳細に説明します。説明不要である場合には、次のセクションまで読み飛ばしてください。
* SGXSDKの前提パッケージをインストールする。
    ``` sh
    sudo apt-get -y install build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl
    ```

* SGXPSWの前提パッケージをインストールする。
    ``` sh
    sudo apt-get -y install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip pkgconf libboost-dev libboost-system-dev libboost-thread-dev lsb-release libsystemd0
    ```

* Linux-SGX（現：confidential-computing.sgx）のリポジトリをクローンする。
    ``` sh
    git clone https://github.com/intel/confidential-computing.sgx/tree/main
    ```

* ディレクトリに入り、導入準備処理バイナリを実行する。
    ``` sh
    cd linux-sgx && make preparation
    ```

* SGXSDKのビルドを実行する。
    ``` sh
    make sdk
    ```

* SGXSDKのインストーラのビルドを実行する。
    ``` sh
    make sdk_install_pkg
    ```

* SGXSDKをインストールする。
    ``` sh
    pushd linux/installer/bin
    sudo ./sgx_linux_x64_sdk_${version}.bin
    ```
    Linux-SGX 2.26の場合、インストーラのファイル名は`sgx_linux_x64_sdk_2.26.100.0.bin`である。  

    今回は、`/opt/intel`にインストールする。以下のように聞かれるので、`no`と入力しEnterする。  
    ``` sh
    Do you want to install in current directory? [yes/no] : no
    ```

    インストール先パスを指定する。
    ``` sh
    Please input the directory which you want to install in : /opt/intel
    ```

* SGXSDKへのパスを通す。Enclaveプログラムをビルドするのであれば、そのセッションで未実施であれば都度実行する必要がある。
    ``` sh
    source /opt/intel/sgxsdk/environment
    ```

* SGXPSWをビルドする。
    ``` sh
    popd
    make psw
    ```

* SGXPSWのインストーラをビルドする。
    ``` sh
    make deb_psw_pkg
    ```

* SGXPSWインストール用のローカルリポジトリをビルドする。
    ``` sh
    make deb_local_repo
    ```

* ビルドしたローカルリポジトリを`apt`に追加するために、`/etc/apt/sources.list`を開き、以下を追記する。
    ``` conf
    deb [trusted=yes arch=amd64] file:/PATH_TO_LOCAL_REPO noble main
    ```  

    `/home/azureuser/Develop/sgx/`配下に`linux-sgx`をクローンしている場合、以下のようになる：
    ``` conf
    deb [trusted=yes arch=amd64] file://home/azureuser/Develop/sgx/linux-sgx/linux/installer/deb/sgx_debian_local_repo noble main
    ```  

    もし、`/etc/apt/sources.list`を開いた時に、  
    ```
    # Ubuntu sources have moved to the /etc/apt/sources.list.d/ubuntu.sources
    # file, which uses the deb822 format. Use deb822-formatted .sources files
    # to manage package sources in the /etc/apt/sources.list.d/ directory.
    # See the sources.list(5) manual page for details.
    ```  
    と出た場合、代わりに`/etc/apt/sources.list.d/ubuntu.sources`に以下を追加する：  
    ``` conf
    Types: deb
    URIs: file:/home/azureuser/Develop/sgx/linux-sgx/linux/installer/deb/sgx_debian_local_repo
    Suites: noble
    Components: main
    Architectures: amd64
    Trusted: yes
    Enabled: yes
    ```

* 追加したリポジトリを反映させる。
    ``` sh
    sudo apt update
    ```  
    以下のような注意表示が出る場合があるが、無視で良い。  
    ```
    N: Download is performed unsandboxed as root as file '/home/azureuser/Develop/sgx/linux-sgx/linux/installer/deb/sgx_debian_local_repo/dists/noble/InRelease' couldn't be accessed by user '_apt'. - pkgAcquire::Run (13: Permission denied)
    N: Missing Signed-By in the sources.list(5) entry for 'file:/home/azureuser/Develop/sgx/linux-sgx/linux/installer/deb/sgx_debian_local_repo'
    ```

* 以下のコマンドを実行し、SGX関連のデバイスに対するアクセス権限を、現在のLinuxユーザに追加する。
    ``` sh
    sudo usermod -aG sgx $USER
    sudo usermod -aG sgx_prv $USER

### DCAPライブラリのインストール[Attester/RP]
* DCAPライブラリをクローンする。
    ``` sh
    git clone --recursive https://github.com/intel/confidential-computing.tee.dcap
    ```
    以前は`SGXDataCenterAttestationPrimitives`というリポジトリ名だったが、2025年後半に改名されている。

* 必要な前提パッケージをインストールする。
    ``` sh
    sudo apt-get install build-essential wget python-is-python3 debhelper zip libcurl4-openssl-dev pkgconf libboost-dev libboost-system-dev libboost-thread-dev protobuf-c-compiler libprotobuf-c-dev protobuf-compiler
    ```

* Quote生成ライブラリのソースフォルダに移動する。
    ``` sh
    cd confidential-computing.tee.dcap/QuoteGeneration/
    ```

* ビルド済みパッケージのダウンロードを行うシェルを実行する。
    ``` sh
    ./download_prebuilt.sh
    ```

* もし現在のログインセッションで未実施の場合、SGXSDKへのパスを通す。
    ``` sh
    source /opt/intel/sgxsdk/environment
    ```

* makeコマンドにより、Quote生成関連ライブラリのビルド・インストールを実行する。
    ``` sh
    make
    ```

* パッケージのビルドを実行する。
    ``` sh
    make deb_pkg
    ```

* 前提パッケージをインストールする。
    ``` sh
    sudo apt install libsgx-headers
    ```

* 生成したdebパッケージが格納されているフォルダに移動する。
    ``` sh
    cd installer/linux/deb/
    ```

* 念の為、開発環境用のライブラリをインストールする。
    ``` sh
    sudo dpkg -i libsgx-dcap-ql-dev_*.deb
    sudo dpkg -i libsgx-dcap-ql-dbgsym_*.ddeb
    ```

* QPL（Quoteのコラテラルをフェッチするライブラリ）をインストールする。
    ``` sh
    sudo dpkg -i libsgx-dcap-default-qpl_*.deb
    sudo dpkg -i libsgx-dcap-default-qpl-dev*.deb
    sudo dpkg -i libsgx-dcap-default-qpl-dbgsym*.ddeb
    ```

* 以下のコマンドを実行し、必要なライブラリのインストールを実施する。
    ``` sh
    sudo apt install libsgx-enclave-common-dev libsgx-dcap-quote-verify-dev libsgx-dcap-default-qpl-dev
    ```

### PCCSの構築[RP]
* 上述までの導入手順により、/etc/sgx_default_qcnl.confが生成されているはずである。念の為、このファイルを適当な場所にバックアップしておく。
    ``` sh
    sudo cp -p /etc/sgx_default_qcnl.conf ~/Develop/sgx/
    ```

* このリポジトリに同梱している `sgx_default_qcnl.conf.pccs` で、 `/etc/sgx_default_qcnl.conf` を上書きする。
    ``` sh
    sudo cp sgx_default_qcnl.conf.pccs /etc/sgx_default_qcnl.conf
    ```  
    念の為、sgx_default_qcnl.confのオーナーや権限についても注意しておく。動作確認済みの環境では以下のようになっている：  
    ``` sh
    -rw-r--r-- 1 root root 747 Dec  4 08:42 /etc/sgx_default_qcnl.conf
    ```

* aesmdサービスの再起動を行い、正常な起動を確認する。
    ``` sh
    sudo systemctl restart aesmd
    systemctl status aesmd
    ```

* 以下のコマンドを実行し、PCCSの前提パッケージのインストールを実施する。
    ``` sh
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -yq --no-install-recommends nodejs=20.11.1-1nodesource1
    sudo apt-get install -y cracklib-runtime
    ```

* PCCSのインストールを実行する。
    ``` sh
    sudo apt install -y --no-install-recommends sgx-dcap-pccs
    ```

実行すると、対話式で色々な入力を求められるため、以下のように入力していく。特に、Caching Fill Methodは必ず`LAZY`を選ぶ事。
    ```
    Do you want to install PCCS now? (Y/N) :y
    Enter your http proxy server address, e.g. http://proxy-server:port (Press ENTER if there is no proxy server) :
    Enter your https proxy server address, e.g. http://proxy-server:port (Press ENTER if there is no proxy server) :

    Do you want to configure PCCS now? (Y/N) :y
    Set HTTPS listening port [8081] (1024-65535) :
    Set the PCCS service to accept local connections only? [Y] (Y/N) :n
    Set your Intel PCS API key (Press ENTER to skip) :<PCS_PRIMARY_KEY>
    Choose caching fill method : [LAZY] (LAZY/OFFLINE/REQ) :LAZY

    Set PCCS server administrator password:<任意のPCCS管理者パスワードを入力>
    Re-enter administrator password:<任意のPCCS管理者パスワードを再入力>
    Set PCCS server user password:<任意のPCCSユーザパスワードを入力>
    Re-enter user password:<任意のPCCSユーザパスワードを再入力>

    Do you want to generate insecure HTTPS key and cert for PCCS service? [Y] (Y/N) :y
    
    Country Name (2 letter code) [AU]:JA
    State or Province Name (full name) [Some-State]:Tokyo
    Locality Name (eg, city) []:shibuya
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:example co., ltd.
    Organizational Unit Name (eg, section) []: 
    Common Name (e.g. server FQDN or YOUR name) []:example.com
    Email Address []:user@example.com

    Please enter the following 'extra' attributes
    to be sent with your certificate request
    A challenge password []:
    An optional company name []:
    ```

#### ベアメタル環境の場合[Attester]
このセクションの手順は、Azureではなくベアメタル環境である場合に実施する。
* PCK Cert ID Retrieval Tool（以下、PCKCIDRT）をインストールする。
    ``` sh
    sudo apt install -y sgx-pck-id-retrieval-tool
    ```

* PCKCIDRTを実行する事で、Platform Manifest等を内包するCSVを取得する。
    ``` sh
    cd /opt/intel/sgx-pck-id-retrieval-tool
    sudo ./PCKIDRetrievalTool -f host_$(hostnamectl --static).csv
    ```
    このCSVは、一度取得するとBIOS設定画面からSGX Factory Resetを実行するまで再取得できなくなるため、慎重に管理する事。

* 以下のコマンドを実行し、CSVからPlatform Manifestをバイナリ形式で抽出する。
    ``` sh
    sudo apt-get install -y csvtool
    sudo bash -c "csvtool col 6 host_$(hostnamectl --static).csv | xxd -r -p > host_$(hostnamectl --static)_pm.bin"
    ```

* 抽出したPlatform Manifestのバイナリを、IRS（Intel Registration Service）に送信し、プラットフォーム登録を実施する。
    ``` sh
    curl -i \
    --data-binary @host_$(hostnamectl --static)_pm.bin \
    -X POST "https://api.trustedservices.intel.com/sgx/registration/v1/platform" \
    -H "Content-Type: application/octet-stream"
    ```

ベアメタル環境固有の操作は上記で終了。  
以下、ベアメタルやAzure等問わず実行する処理の説明に戻るが、DCAPバージョンが1.24以上であるか否かで手順が分かれる。

#### DCAPバージョンが1.24以上の場合[Attester/RP]
* Attesterにて、DCAP公式ライブラリ内の、PCS Client Toolのフォルダに移動する。以下、明記があるまでAttesterでの手順。
    ``` sh
    cd confidential-computing.tee.dcap/tools/PcsClientTool/
    ```

* ベアメタル環境である場合、先程取得したCSVをコピーしてくる。
    ``` sh
    cp /opt/intel/sgx-pck-id-retrieval-tool/host_$(hostnamectl --static).csv .
    ```

* pip3をインストールする。
    ``` sh
    sudo apt install python3-pip
    ```

* venvを有効化し、前提パッケージをインストールする。
    ``` sh
    sudo apt install python3-venv
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

* PCS Client Toolにより、プラットフォームリストの取得を行い、そして全てのFMSPCに対するコラテラルを取得する。実行後はdeactivateコマンドによりvenv環境を抜けておく。
    ``` sh
    ./pcsclient.py collect -d . -o platform_list.json
    ./pcsclient.py fetch -p all -t early -o platform_collaterals.json
    deactivate
    ```
    fetchの方を実行すると以下のように聞かれるため、以下のように入力する。APIキーには自身のPCSプライマリキーを入力する。
    ```
    Please input ApiKey for Intel PCS:
    Would you like to remember Intel PCS ApiKey in OS keyring? (y/n)n
    ```

* RPとAttesterが別々のマシンである場合、上記`platform_collaterals.json`を、AttesterからRPに`scp`等で転送しておく。

* 以下、RPでの手順。作業フォルダに戻り、PCCS Admin ToolをCloneする。
    ``` sh
    git clone --recursive https://github.com/intel/confidential-computing.tee.dcap.pccs.git
    ```

* Cloneしたフォルダに入り、さらにその中のPccsAdminToolフォルダに入り、venv環境を生成する。
    ``` sh
    cd confidential-computing.tee.dcap.pccs/PccsAdminTool
    python3 -m venv venv
    source venv/bin/activate
    ```

* PCCS Admin Toolにより、収集したコラテラルをPCCSに登録する。
    ``` sh
    ./pccsadmin.py put -i platform_collaterals.json
    deactivate
    ```
    実行すると以下のように聞かれるため、以下のように入力する。PCCS管理者パスワードは先程決めたものを入力する。
    ```
    Please input your administrator password for PCCS service:
    Would you like to remember password in OS keyring? (y/n)n
    ```

#### DCAPバージョンが1.23以下の場合[Attester/RP]
* Attesterにて、DCAP公式ライブラリ内の、PCCS Admin Toolのあるフォルダに移動する。以下、明記があるまでAttesterでの手順。
    ``` sh
    cd ~/Develop/sgx/confidential-computing.tee.dcap/tools/PccsAdminTool
    ```

* pip3をインストールする。
    ``` sh
    sudo apt install python3-pip
    ```

* venvを有効化し、前提パッケージをインストールする。
    ``` sh
    sudo apt install python3-venv
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

* PCCS Admin Toolにより、プラットフォームリストの取得を行い、そして全てのFMSPCに対するコラテラルを取得する。
    ``` sh
    ./pccsadmin.py collect -d . -o platform_list.json
    ./pccsadmin.py fetch -p all -t early -o platform_collaterals.json
    ```
    fetchの方を実行すると以下のように聞かれるため、以下のように入力する。APIキーには自身のPCSプライマリキーを入力する。
    ```
    Please input ApiKey for Intel PCS:
    Would you like to remember Intel PCS ApiKey in OS keyring? (y/n)n
    ```

* RPとAttesterが別々のマシンである場合、上記`platform_collaterals.json`を、AttesterからRPに`scp`等で転送しておく。

* 以下、RPでの手順。上記で取得したコラテラルのリスト（`platform_collaterals.json`）を、PCCS Admin Toolを用いてPCCSに投入する。
    ``` sh
    ./pccsadmin.py put   -i platform_collaterals.json
    ```
    実行すると以下のように聞かれるため、以下のように入力する。PCCS管理者パスワードは先程決めたものを入力する。
    ```
    Please input your administrator password for PCCS service:
    Would you like to remember password in OS keyring? (y/n)n
    ```

#### 全バージョン共通手順の続き[RP/Attester]
* もし前の手順において、PCCSのCaching Fill MethodをLAZYにしていない場合は、`/opt/intel/sgx-dcap-pccs/config/default.json`を開き、`CachingFillMode`フィールドのエントリを`LAZY`に変更する。

* 確実にPCSではなくPCCSのコラテラルが来ている事を確かめるには、以下の構成にしてRAの実験をすると良い。
    * `sgx_default_qcnl.conf`の`collateral_service`フィールドのエントリを、PCCSのURL、つまり`https://localhost:8081/sgx/certification/v4/`にする。
    * ローカルキャッシュ、つまり`/home/azureuser/.dcap-qcnl`フォルダ直下を全削除する。

## 準備
### https通信用のCA証明書の準備
本リポジトリではデフォルトでリポジトリのディレクトリ内に`ca-certificates.crt`の形でCA証明書を同梱しています（Ubuntu 24.04の環境からそのまま持ってきたものです）。

自前のものを用意したい場合、
* Ubuntuの場合: `/etc/ssl/certs/ca-certificates.crt`
* CentOSの場合: `/etc/pki/tls/certs/ca-bundle.crt`  

等からコピーし、ファイル名は`ca-certificates.crt`としてください。

### クライアントの署名用キーペアの生成・ハードコーディング
RAのセッション鍵のベースとなる共有秘密生成用のキーペア（ランタイム時に乱数的に生成される）とは別に、クライアントが両者の公開鍵の連結に対する署名を打つために使用し、またその署名をSGXサーバが検証する際に使用する、256bit ECDSAキーペアが必要になります。

このキーペアは、公開鍵をSGXサーバ側のEnclaveコード（`Server_Enclave/server_enclave.cpp`）にハードコーディングし、秘密鍵をクライアントのコード（`Client_App/client_app.cpp`）にハードコーディングする必要があります（改竄防止のため、特に公開鍵についてはEnclaveコードへのハードコーディングがほぼ必須です）。

デフォルトでもこちらで乱数的に用意したキーペアをハードコーディングしてありますので、そのままでも問題なくRAを実行する事が出来ますが、自前のキーペアを用いたい場合は同梱の補助ツールである`client-ecdsa-keygen`を使用できます。

このツールは、ECDSAキーペアを生成してソースコードライクに標準出力するもので、出力をコピペする事で簡単にハードコーディングを行う事が出来ます。

以下、これを用いたキーペア生成及びハードコーディングの手順を説明します：

* `client-ecdsa-keygen`が配置されているパスに移動する。
    ```
    cd subtools/client-ecdsa-keygen/
    ```

* `make`コマンドでビルドする。
    ```
    make
    ```

* ビルドにより生成された実行ファイルを実行する。
    ```
    ./keygen
    ```

* 以下のような内容が標準出力される。
    ```
    （前略）
    Copy the following public keys and hardcode them into Server's Enclave code (ex: server_enclave.cpp):

        {
                0xb5, 0x72, 0x2f, 0xb9, 0x04, 0x2d, 0xcd, 0xd9,
                0x73, 0x63, 0x42, 0x4b, 0xe2, 0xda, 0xb8, 0x7c,
                0x58, 0xf6, 0x5c, 0x5d, 0x58, 0xe8, 0x71, 0xda,
                0x69, 0x12, 0x33, 0x5b, 0x9b, 0xee, 0x73, 0x80
        },
        {
                0xef, 0x69, 0x4d, 0x3c, 0x92, 0x99, 0xae, 0x25,
                0xf4, 0x7c, 0xb8, 0x36, 0xad, 0x11, 0x47, 0x27,
                0xfa, 0x0c, 0x7d, 0xd1, 0x5d, 0x6a, 0x08, 0xd7,
                0xff, 0x01, 0x41, 0xda, 0x72, 0x19, 0xc7, 0x7f
        }



    Copy the following private key and hardcode it into Client's untrusted code (ex: client_app.cpp):

            0x1e, 0xe0, 0x50, 0x82, 0x08, 0x57, 0x91, 0x17,
            0xa9, 0xe8, 0x51, 0x27, 0x5f, 0xf5, 0x19, 0xec,
            0xe7, 0xa9, 0x83, 0x80, 0x8d, 0xd8, 0xbc, 0x3b,
            0x5c, 0xdb, 0x2c, 0x64, 0x2a, 0x33, 0xde, 0xd6
    ```

* 上記表示の内、公開鍵の方（上側2ブロック）を、`Server_Enclave/client_pubkey.hpp`の`static const sgx_ec256_public_t client_signature_public_key`変数の中に以下のようにコピー&ペーストする。
    ``` cpp
    static const sgx_ec256_public_t client_signature_public_key[2] = {
        {
            //デフォルトのclient_app.cppの鍵に対応するのはこちらの値。
            {
                0xb0, 0x81, 0x99, 0x7f, 0xac, 0xe4, 0xdd, 0x8a,
                0x38, 0x72, 0x71, 0x3b, 0xb7, 0xce, 0xe0, 0xcb,
                0xe3, 0xed, 0xaa, 0xe1, 0x9d, 0x60, 0x10, 0x55,
                0x59, 0x2c, 0x4f, 0x36, 0x4f, 0xe5, 0x18, 0x35
            },
            {
                0x33, 0x89, 0xd3, 0x07, 0x14, 0x3d, 0x2e, 0x2d,
                0x1f, 0x70, 0x69, 0x33, 0x9b, 0x27, 0x9a, 0x73,
                0x7f, 0x6d, 0x71, 0x76, 0x55, 0x83, 0xfa, 0x0a,
                0x81, 0xc8, 0x3e, 0x84, 0xac, 0x36, 0xbf, 0xad
            }
        },
        {
            //こちらは2クライアント目のプレースホルダーであるダミー。
            //実際に使用する際は差し替える事。3クライアント目以降は自前で追加。
            {
                0xb7, 0x6a, 0xce, 0x37, 0x02, 0x20, 0xeb, 0x93,
                0xd2, 0xf8, 0xb6, 0xdc, 0xa0, 0x3d, 0x44, 0xcf,
                0xd0, 0x40, 0xaf, 0x93, 0x75, 0x77, 0x66, 0x27,
                0xf9, 0xad, 0x40, 0xf3, 0xe5, 0x9b, 0xd0, 0xc3
            },
            {
                0x6c, 0x47, 0xe7, 0x78, 0xe3, 0xac, 0x5e, 0x1f,
                0xe6, 0x9a, 0xfe, 0xdc, 0x86, 0x5b, 0x34, 0xbc,
                0x92, 0xb0, 0x1f, 0x94, 0xb5, 0x43, 0xfb, 0x7e,
                0x9a, 0xf2, 0x54, 0x9f, 0xc2, 0x0b, 0x6c, 0x2c
            }
        }
    };
    ```
    この署名検証用公開鍵格納変数は`sgx_ec256_public_t`型の配列となっているため、クライアントの数の分だけ手動で追加し複数クライアントを相手にする事ができる。

* 同様に、秘密鍵の方（最後のブロック）を、`Client_App/client_app.cpp`の`static const uint8_t g_client_signature_private_key[32]`変数の中に以下のようにコピー&ペーストする。
    ``` cpp
    static const uint8_t g_client_signature_private_key[32] = {
        0xef, 0x5c, 0x38, 0xb7, 0x6d, 0x4e, 0xed, 0xce,
        0xde, 0x3b, 0x77, 0x2d, 0x1b, 0x8d, 0xa7, 0xb9,
        0xef, 0xdd, 0x60, 0xd1, 0x22, 0x50, 0xcc, 0x90,
        0xc3, 0xb5, 0x17, 0x54, 0xdc, 0x2f, 0xe5, 0x18
    };
    ```

### Enclave署名鍵の設定
Enclaveの署名に使用する鍵は、デフォルトで`Server_Enclave/private_key.pem`として格納しており、これを使用しています。

ただ、実運用時には自前で生成したものを使用するのが望ましいため、以下のコマンドにて新規に作成し、上記のパスに同名でその鍵を格納してください。

```
openssl genrsa -out private_key.pem -3 3072
```


### 通信の設定
デフォルトではクライアントとSGXサーバ共に同一のマシン上に配置し、ローカルホストでポート1234を通して相互に通信する設定になっています。

この通信情報を変更したい場合、クライアントとSGXサーバでそれぞれ以下の箇所を編集する事で変更を行う事が出来ます。

* クライアントの場合：`Client_App/client_app.cpp`の以下の箇所を編集してください。
    ``` cpp
    std::string server_url = "http://localhost:1234";
    ```
    編集例：
    ``` cpp
    std::string server_url = "http://example.com:1234";
    ```

* SGXサーバの場合：`Server_App/server_app.cpp`の以下の箇所を編集してください。
    ``` cpp
    svr.listen("localhost", 1234);
    ```
    編集例：
    ``` cpp
    svr.listen("0.0.0.0", 1234);
    ```
    デフォルトでは明示的にローカルホストである事を明記するために`"localhost"`としていますが、基本的に`"0.0.0.0"`で問題ないはずです。より詳細は[cpp-httplibのリポジトリ](https://github.com/yhirose/cpp-httplib)を参照してください。


## ビルド・設定・実行
### ビルド
準備が整ったら、Humane-RAFW-DCAPのルートフォルダに移動し、makeコマンドでビルドを実行します。
```
make
```

以下のようなビルドログが出力されれば正常にビルドされています。
```
user@machine:~/Develop/sgx/Humane-RAFW-DCAP$ make
GEN  =>  Server_App/server_enclave_u.c
CC   <=  Server_App/server_enclave_u.c
CXX  <=  Server_App/server_app.cpp
CXX  <=  common/error_print.cpp
CXX  <=  common/base64.cpp
CXX  <=  common/debug_print.cpp
CXX  <=  common/hexutil.cpp
CXX  <=  common/crypto.cpp
LINK =>  server_app
GEN  =>  Server_Enclave/server_enclave_t.c
CC   <=  Server_Enclave/server_enclave_t.c
CXX  <=  Server_Enclave/server_enclave.cpp
/usr/bin/ld: warning: memmove.o: missing .note.GNU-stack section implies executable stack
/usr/bin/ld: NOTE: This behaviour is deprecated and will be removed in a future version of the linker
LINK =>  enclave.so
<!-- Please refer to User's Guide for the explanation of each field -->
<EnclaveConfiguration>
    <ProdID>0</ProdID>
    <ISVSVN>0</ISVSVN>
    <StackMaxSize>0x40000</StackMaxSize>
    <HeapMaxSize>0x5000000</HeapMaxSize>
    <TCSNum>10</TCSNum>
    <TCSPolicy>1</TCSPolicy>
    <DisableDebug>1</DisableDebug>
    <MiscSelect>0</MiscSelect>
    <MiscMask>0xFFFFFFFF</MiscMask>
    <EnableKSS>1</EnableKSS>
    <ISVEXTPRODID_H>1</ISVEXTPRODID_H>
    <ISVEXTPRODID_L>2</ISVEXTPRODID_L>
    <ISVFAMILYID_H>3</ISVFAMILYID_H>
    <ISVFAMILYID_L>4</ISVFAMILYID_L>
</EnclaveConfiguration>
tcs_num 10, tcs_max_num 10, tcs_min_pool 1
INFO: Enclave configuration 'MiscSelect' and 'MiscSelectMask' will prevent enclave from using dynamic features. To use the dynamic features on SGX2 platform, suggest to set MiscMask[0]=0 and MiscSelect[0]=1.
The required memory is 89649152B.
The required memory is 0x557f000, 87548 KB.
Succeed.
writing RSA key
<!-- Please refer to User's Guide for the explanation of each field -->
<EnclaveConfiguration>
    <ProdID>0</ProdID>
    <ISVSVN>0</ISVSVN>
    <StackMaxSize>0x40000</StackMaxSize>
    <HeapMaxSize>0x5000000</HeapMaxSize>
    <TCSNum>10</TCSNum>
    <TCSPolicy>1</TCSPolicy>
    <DisableDebug>1</DisableDebug>
    <MiscSelect>0</MiscSelect>
    <MiscMask>0xFFFFFFFF</MiscMask>
    <EnableKSS>1</EnableKSS>
    <ISVEXTPRODID_H>1</ISVEXTPRODID_H>
    <ISVEXTPRODID_L>2</ISVEXTPRODID_L>
    <ISVFAMILYID_H>3</ISVFAMILYID_H>
    <ISVFAMILYID_L>4</ISVFAMILYID_L>
</EnclaveConfiguration>
tcs_num 10, tcs_max_num 10, tcs_min_pool 1
INFO: Enclave configuration 'MiscSelect' and 'MiscSelectMask' will prevent enclave from using dynamic features. To use the dynamic features on SGX2 platform, suggest to set MiscMask[0]=0 and MiscSelect[0]=1.
The required memory is 89649152B.
The required memory is 0x557f000, 87548 KB.
handle_compatible_metadata: Overwrite with metadata version 0x100000005
Succeed.
SIGN (two-step) =>  enclave.signed.so
CXX  <=  Client_App/client_app.cpp
CXX  <=  common/jwt_util.cpp
LINK =>  client_app
```

### 設定
実行する前に、クライアントがRAで使用する設定情報を`settings_client.ini`に記載します。**デフォルトでは`settings_client_template.ini`というファイル名になっているので、必ずこれを`settings_client.ini`にリネームしてから使用してください**。

以下、`settings_client.ini`における各必須設定項目（キー）についての説明を列挙します（いずれの値もダブルクオーテーションは不要）：
| 設定項目 | 説明 | 推奨値 |
| -- | -- | -- |
| CLIENT_ID | クライアントのIDを指定する。「準備」のセクションで登録した、`Server_Enclave/client_pubkey.hpp`にハードコーディングしてある署名検証用公開鍵配列の`client_signature_public_key`におけるインデックスに等しい。単一クライアントでのみ運用する場合は常時0で良い。 | - |
| MINIMUM_ISVSVN | クライアントがSGXサーバに要求する最小ISVSVN値。ISVSVNは、`Server_Enclave/Enclave.config.xml`において`<ISVSVN>`タグでSGXサーバ側が設定する。 | Enclave設定ファイルで設定した値以上 |
| REQUIRED_ISV_PROD_ID | クライアントがSGXサーバに要求するISV Product ID値。ISV Product IDは、`Server_Enclave/Enclave.config.xml`において`<ProdID>`タグでSGXサーバ側が設定する。 | Enclave設定ファイルで設定した値 |
| REQUIRED_MRENCLAVE | SGXサーバに要求するMRENCLAVE値。クライアントは予めEnclaveのMRENCLAVEを控えておき（=ここで設定する内容）、RAにおいてSGXサーバから受け取ったQuote構造体に含まれるMRENCLAVEと比較検証を行う。この値の取得方法は後述。 | Enclaveに期待するMRENCLAVE値 |
| REQUIRED_MRSIGNER | SGXサーバに要求するMRSIGNER値。クライアントは予めEnclaveのMRSIGNERを控えておき（=ここで設定する内容）、RAにおいてSGXサーバから受け取ったQuote構造体に含まれるMRSIGNERと比較検証を行う。この値の取得方法は後述。 | Enclaveに期待するMRSIGNER値 |
| SKIP_MRENCLAVE_CHECK | 1に設定すると、RAにおいてMRENCLAVEの検証をスキップする。MRENCLAVEはEnclaveのコード等が変わる度に値が変わるため、開発時には煩雑であり、それを一時的に便宜上スキップするためのオプション。**実運用時は必ず0にする事**。 | 0 |
| ALLOW_SW_HARDENING_NEEDED | RAステータスが`SW_HARDENING_NEEDED`を含んでいてもRAを受理するか。0で拒否、1で許容。他のステータスも含むようなRAステータスの場合（例：`TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED`）、そちらについての指定も1にしておかないとRAは受理されない。 | 基本0だが、最新化が不可能な場合（例：Azureを使用している）は1 |
| ALLOW_CONFIGURATION_NEEDED | RAステータスが`CONFIGURATION_NEEDED`を含んでいてもRAを受理するか。0で拒否、1で許容。他のステータスも含むようなRAステータスの場合（例：`TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED`）、そちらについての指定も1にしておかないとRAは受理されない。 | 同上 |
| ALLOW_OUT_OF_DATE | RAステータスが`OUT_OF_DATE`を含んでいてもRAを受理するか。0で拒否、1で許容。他のステータスも含むようなRAステータスの場合（例：`TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED`）、そちらについての指定も1にしておかないとRAは受理されない。 | 同上 |
| ALLOW_DEBUG_ENCLAVE | DebugモードのEnclaveを許可するか。0で拒否、1で許容。**実運用時は必ず0にする事**。 | 0 |
| ALLOW_COLLATERAL_EXPIRATION | コラテラルの期限切れを許容するか。0で拒否、1で許容。 | コラテラルを最新化できる環境であれば0。Azureのように難しければ1 |
| ALLOW_SMT_ENABLED | Enclaveが載るマシンのハイパースレッドの有効化を許容するか。0で拒否、1で許容 | ハイパースレッドは各種攻撃を効率化する性質を持つので原則として0 |
| ALLOWED_SA_LIST | 許容するセキュリティアドバイザリ（SA）のリスト。複数指定する場合はカンマ区切りで列挙する。必ずINTEL-SA-XXXXXのように、数字部分は5桁にする（例：ALLOWED_SA_LIST = INTEL-SA-00086, INTEL-SA-00615, INTEL-SA-01153）。無条件に全てのセキュリティアドバイザリを許容する場合、右辺は「ALL」とだけ記載する。一切許容しない場合には、「none」とだけ記載する。 | 理想的にはnoneだが、脆弱性の内容や危険性を鑑みて場合によっては必要最低限を記載（許可）する |

次に、同ファイル内における各任意設定項目についての説明を列挙します（いずれの値もダブルクオーテーションは不要）：
| 設定項目 | 説明 | 推奨値 |
| -- | -- | -- |
| MINIMUM_TCB_EVAL_DATASET_NUM | 期待するTCB Evaluation Dataset Numberの下限値。整数で指定。指定不要な場合は0と記載する。 | [こちら](https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/trusted-computing-base-recovery-attestation.html)の表にある「TCB-R Counter:」の次に書かれている数字と、その列の内容を見て判断する。理想的にはその時点での最新値（2025/12/19では20） |
| REQUIRED_ISV_EXT_PROD_ID_HIGHER | 期待するISV Extended Product IDの上位8バイト。10進数で指定。指定不要な場合はnoneと記載する（その場合、LOWERの方もnoneにする）。 | Enclave設定ファイルで設定した値。当該KSS値未使用時にはnone |
| REQUIRED_ISV_EXT_PROD_ID_LOWER | 期待するISV Extended Product IDの下位8バイト。10進数で指定。指定不要な場合はnoneと記載する（その場合、HIGHERの方もnoneにする）。 | Enclave設定ファイルで設定した値。当該KSS値未使用時にはnone |
| REQUIRED_ISV_FAMILY_ID_HIGHER | 期待するISV Family IDの上位8バイト。10進数で指定。指定不要な場合はnoneと記載する（その場合、LOWERの方もnoneにする）。 | Enclave設定ファイルで設定した値。当該KSS値未使用時にはnone |
| REQUIRED_ISV_FAMILY_ID_LOWER | 期待するISV Family IDの下位8バイト。10進数で指定。指定不要な場合はnoneと記載する（その場合、HIGHERの方もnoneにする）。 | Enclave設定ファイルで設定した値。当該KSS値未使用時にはnone |
| REQUIRED_CONFIG_ID | 期待するConfig ID値。Hex表現の128文字（バイナリに直すと64Bになる）で指定する。指定不要な場合はnoneと記載する。 | `server_app.cpp`の`sgx_create_enclave_ex()`に渡しているConfig ID値 |
| MINIMUM_CONFIG_SVN | 期待するConfig SVNの下限値。整数（uint16_t）で指定。指定不要な場合は0と記載する。 | `server_app.cpp`の`sgx_create_enclave_ex()`に渡しているConfig SVN値以上 |
| MINIMUM_PCE_SVN | 期待するPCE SVNの下限値。整数（uint16_t）で指定。指定不要な場合は0と記載する。 | 指定なし。指定をしたい場合には、一度確実に正しいPCEが使われている環境で本リポジトリにてRAを行い、標準出力された値を設定 |
| MINIMUM_QE_SVN | 期待するQE3 SVNの下限値。整数（uint16_t）で指定。指定不要な場合は0と記載する。 | 同上 |
| REQUIRED_QE_PROD_ID | 使用されるQE3に期待するProd ID値。整数（uint16_t）で指定。指定不要な場合はnoneと記載する。 | 同上 |
| REQUIRED_QE_MRENCLAVE | 使用されるQE3に期待するMRENCLAVEを指定する。いずれもHex表現の64文字（バイナリに直すと32B）で指定する。指定不要な場合はnoneと記載する。 | 同上 |
| REQUIRED_QE_MRSIGNER | 使用されるQE3に期待するMRSIGNERを指定する。いずれもHex表現の64文字（バイナリに直すと32B）で指定する。指定不要な場合はnoneと記載する。 | 同上 |

上記`REQUIRED_MRENCLAVE`及び`REQUIRED_MRSIGNER`で指定するMRENCLAVEやMRSIGNERは、補助ツールである`mr-extract`を使用する事で、署名済みEnclaveイメージから抽出し簡単に取得する事が出来ます。

以下、これを用いた各値の抽出方法を説明します：
* Humane-RAFW-DCAP本体をビルドし、署名済みEnclaveイメージがビルドされ存在している事を確認する。
    ``` bash
    user@machine:~/Develop/sgx/Humane-RAFW-DCAP$ ls -l enclave.signed.so 
    -rw-rw-r-- 1 user user 3295136 Dec 19 07:45 enclave.signed.so
    user@machine:~/Develop/sgx/Humane-RAFW-DCAP$
    ```

* `mr-extract`が配置されているパスに移動する。
    ```
    cd subtools/mr-extract/
    ```

* `make`コマンドでビルドする。
    ```
    make
    ```

* ビルドにより生成された実行ファイルを実行する。
    ```
    ./mr-extract
    ```
    SGXSDKのパスが`/opt/intel/sgxsdk/`、署名済みEnclaveイメージ名が`mr-extract`フォルダ内から見て`../../enclave.signed.so`以下の通りではない場合は、以下のようにそれぞれ`-t`、`-e`オプションで場所を指定できる。
    ```
    ./mr-extract -t <SGXSDK_PATH> -e <ENCLAVE_PATH>
    ```

* 以下のような内容が標準出力される。
    ```
    -------- message from sgx_sign tool --------
    Succeed.
    --------------------------------------------

    Copy and paste following measurement values into settings.ini.
    MRENCLAVE value -> c499d7bf5c0f9fe6f7cee583e3fdaca722faa9507c17b6e317a386e0f6eeb194
    MRSIGNER value  -> babdf7eb81e8f91f1d14fa70200f76c4b49b85a3caf591faa3761d3b5910a9d5
    ```
    この例で言えば、`c499d7bf5c0f9fe6f7cee583e3fdaca722faa9507c17b6e317a386e0f6eeb194`を`REQUIRED_MRENCLAVE`に、`babdf7eb81e8f91f1d14fa70200f76c4b49b85a3caf591faa3761d3b5910a9d5`を`REQUIRED_MRSIGNER`に設定する。

### 実行
ビルドと設定が完了したら、まずSGXサーバは以下のコマンドでSGXサーバを起動します：
```
./server_app
```

SGXサーバが起動したら、クライアントは以下のコマンドでクライアントアプリケーションを実行します：
```
./client_app
```

その後はRAが実行され、RAを受理した場合にはクライアントは秘密情報をRAのセッション鍵で暗号化してSGXサーバに送信し、SGXサーバがEnclave内で秘密情報を足し合わせ、その結果を暗号化してクライアントに返却する、ごく簡単な秘密計算の例が実行されます。


## 本フレームワークの応用
### 暗号処理関数
秘密計算サンプル関数（`sample_remote_computation()`）でも使用されている`aes_128_gcm_encrypt()`関数、`aes_128_gcm_decrypt()`関数、そして`generate_nonce()`関数は、それぞれRAのセッション鍵を用いた暗号化・復号、そして初期化ベクトル等の乱数的な生成に使用する事が出来ます。

### 通信におけるデータ形式
クライアントとSGXサーバの間におけるデータの通信においては、各値をBase64にエンコードし、JSON形式でそれらを格納してやり取りしています。

### RAフレームワークコードの完全な切り離し
デフォルトでは、クライアントは`Client_App/client_app.cpp`、SGXサーバは`Server_App/server_app.cpp`にmain関数（RA実行関数を呼び出す関数）を定義しています。  
RA部分を自前のコードファイルから完全に切り離したい場合は、main関数等を自前のコードファイルで定義し、Makefileを適宜書き換えてください。  

例えば、`Client_App/my_program.cpp`を新たに追加し、この中でmain関数を宣言してRAを呼び出す場合、以下の部分：
``` makefile
## コンパイル時に使用するC/C++のソースを列挙
Client_Cpp_Files := Client_App/client_app.cpp common/base64.cpp common/debug_print.cpp common/hexutil.cpp \
				common/crypto.cpp

```
に、以下のようにソースコードを追加します：
``` makefile
## コンパイル時に使用するC/C++のソースを列挙
Client_Cpp_Files := Client_App/client_app.cpp common/base64.cpp common/debug_print.cpp common/hexutil.cpp \
				common/crypto.cpp Client_App/my_program.cpp

```

### 複数クライアントへの対応
デフォルトでは単一のSGXサーバに対して単一のクライアントを対応させている形ですが、複数のクライアントを対応させるように改修する事も可能です。

既に、SGXサーバはRAコンテキスト値によりRAセッションを識別し、クライアントもRAコンテキスト値を保持して適宜SGXサーバに渡す実装になっています。

よって、Untrusted領域レベルのロジックでのクライアントの識別や、クライアントの署名検証用公開鍵のEnclaveコードへのハードコーディング周りを整備すれば、複数クライアントへの対応についても実現する事が出来ます。

## 使用している外部ライブラリ
いずれもヘッダオンリーライブラリであり、リポジトリに組み込み済み（`include/`フォルダ内）。
* [cpp-httplib](https://github.com/yhirose/cpp-httplib): MITライセンス
* [SimpleJSON](https://github.com/nbsdx/SimpleJSON): WTFPLライセンス
* [mINI](https://github.com/pulzed/mINI): MITライセンス

## その他仕様や注意点
### AEの動作モード
DCAP-RAにおけるQuote生成では、PCE（Platform Certification Enclave）やQE3（Quoting Enclave for 3rd party attestation）といったAEや関連の各種サービスを、Quote生成プロセス内で動作させるモードとプロセス外で動作させるモードが存在します。  
前者のプロセス内で動作させるモードはIn-Procモード、後者のプロセス外のデーモン（AESM）に任せるモードはOut-of-Procと呼ばれます。  
（参考：[https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-aks-addon](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-aks-addon)）

AzureのDCsv3マシンでは、基本的にOut-of-Procモードのみに対応しており、In-Procモードへの切り替えは手元では成功していません。  
よって、Azureとの互換性も鑑みて、Humane-RAFW-DCAPではOut-of-Procモードを前提として実装されている点に注意してください。  

稀に、SGXサーバ側でQuoteを生成するタイミングで、このOut-of-Procのための裏で動いているサービスが落ちている場合があります。その場合はQuoteを生成できずに異常終了するように実装していますが、経験上数分も待てば正常に戻る事を確認しています。

### QPL用の設定JSONファイル
`/etc/`配下に配置するQPL用の設定ファイルである`sgx_default_qcnl.conf`はJSON形式であるため、少しでもJSONのフォーマットにエラーがあったりすると、QPLがコラテラルをフェッチできず、不完全なQuoteが生成されてしまいます。  

この不完全なQuoteを使用するとエラーに繋がるため、本リポジトリに同梱した設定ファイルをそのままコピー&ペーストするなどにより、JSONに誤りが混じらないように十分注意してください。

### Enclaveのモード
旧来のEPID-RAでは、Intelからのライセンスが降りていないと製品版Enclave向けRAのためのIASのAPIを使用できなかったため、Humane-RAFWにおいてはデフォルトではデバッグ版での動作を想定していました。  

しかし、DCAP-RAではそのような制約も存在しないため、製品版（Production）モードでEnclaveをビルドしRAを実行するようにしています。  
それに伴い、Enclaveへの署名方法についても、シングルステップ署名ではなく2ステップ署名を行うようにしています。2ステップ署名の全ての処理はmakeで自動化されていますが、厳密に管理された環境やデバイス（HSM等）での署名を望む場合は、適宜Makefileを書き換えながらオフロードしてください。

## ライセンスについて
本リポジトリの内容は、[Humane-RAFW-MAA](https://github.com/acompany-develop/Humane-RAFW-MAA/)をベースに、同一の開発者が開発しています。Humane-RAFW-MAA内に含まれる内容の流用・改造部分に関しては、Humane-RAFW-MAAに従いMITライセンスを継承します。また、本リポジトリで新規追加した内容についても、同様にMITライセンスで公開します。

## 謝辞
本研究は、JST経済安全保障重要技術育成プログラム【JPMJKP24U4】の支援を受けたものです。
