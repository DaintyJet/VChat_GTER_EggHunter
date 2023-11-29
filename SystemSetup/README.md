# System Configuration
This document covers the configuration of bot the victim and attacking machines. Of course the configurations, and packages will vary between Operating Systems (OS) and even the version of the OS used. The specific system and their requirements will be explicitly specified. If you use a different OS, and sometimes version of an OS you may experience different results. 

This document describes the general setup for the **victim** and **attacker** machines. The specific uses of each application.

## Repository Structure
Each exploit has its **own** directory. Within the directory for each exploit there are a few additional subdirectories.
1. Images: Contains images related to the exploit used in the documentation
2. Metasploit: Custom Metasploit modules to execute the exploit (If applicable)
3. SourceCode: Contains asm, python or C++ code associated with the exploit 

Each exploit will contain a **README.md** describing the exploit, concepts related to the exploit, and why the exploit works the way it does in addition to the countermeasures that can be taken to prevent them (if possible).
## Victim (Vulnserver) System
Vulnserver **only** runs on windows machines, take not of the ```.exe``` file extension, usually this means the file is in the Windows **[Portable Executable (PE)](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)** Format. If you attempt to run this on a Linux machine without a compatibility layer as was done with a modified Vulnserver in the repository [VChat with Wine](https://github.com/DaintyJet/vChat_On_Linux) it will not work.

### Windows 10
To exploit Vulnserver.exe running on a Windows 10 machine we need to make the following modifications to the machine's settings, and you will also need to install additional applications or programs.

#### Configuration
1. Disable [Windows exploit protections](https://github.com/llanShiraishi/WinExploit).
  - That is a private or deleted repository...
  - For exploits bypassing defenses, this may be reenabled.
2. Disable the firewall on the Windows machine. ([How to Allow Ping through the Firewall in Windows 10](https://www.faqforge.com/windows/windows-10/how-to-allow-ping-trough-the-firewall-in-windows-10/)).
#### Applications
1. [Install](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) Git for windows. This is so we can clone (download) the Vulnserver application's repository.
2. [Download](https://github.com/stephenbradshaw/vulnserver) Vulnserver
   * A modified version that includes chat features is included in Prof. Xinwen Fu's [repository](https://github.com/xinwenfu/vchat). This is not used here.
3. [Install](https://www.immunityinc.com/products/debugger/) Immunity Debugger. 
4. [Install](https://github.com/corelan/mona) Mona extension for the Immunity Debugger.
5. (Optional) [Install](https://visualstudio.microsoft.com/) Visual Studio.
    * This is Optional as you can pre-compile the executable on your own Windows System and move it to the vulnerable system when necessary.
## Attacking System
There are two ways to run the exploits, we can run the associated **python** scripts, or a custom **Metasploit Module** provided for each of the attacks. In both cases we will need a machine with Metaspoit installed, this is because some of the exploits require data that is generated, or interpreted by a Metasploit command such as ```msfvenom``` or ```msf-pattern_offset``` to name two. Additionally if we are using the python scripts python will need to be installed. Something to take note of is that the **attacking system** can be a **Windows** or **Linux** machine. Some attacks may need additional exploitations tools, and they will also be specified in the documents related to the specific attack. Generally we will make the assumption that a [Kali Linux](https://www.kali.org/get-kali/#kali-platforms) distribution of Linux is used as this will have most if not all of the exploitation tools pre-installed, and any additional tools are easily installed from their source repository. 

**Note**: We suggest the use of Kali Linux, as this simplifies the process. However some of the necessary tools are listed below.

1. [Install](https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/) the Metasploit Framework.
2. [Install] Python if it is not already installed.
    ```
    sudo apt-get update && \
    sudo apt-get install python
    ```
   * **Note**: You should be aware, if you set this up on a different Linux distribution you will need to use a different package manager! 
3. [Install](https://www.kali.org/tools/spike/) SPIKE Protocol Fuzzer 
    * This is also available as source code on [GitHub](https://github.com/guilhermeferreira/spikepp)