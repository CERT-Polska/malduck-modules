rule cobalt_strike
{
	meta:
		author = "Elastic Security, Matthew @ Embee_Research"
		creation_date = "2021-03-23"
		last_modified = "2023-11-04"
		description = "Attempts to detect Cobalt Strike based on number of signatures related to BEACON"
		os = "Windows"
		arch = "x86, x64"
		category_type = "Trojan"
		family = "CobaltStrike"
		threat_name = "Windows.Trojan.CobaltStrike"

	strings:
		$a1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a2 = "%s.3%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a3 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset." ascii fullword
		$a4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" ascii fullword
		$a5 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii fullword
		$a6 = "%s.2%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a7 = "could not run command (w/ token) because of its length of %d bytes!" ascii fullword
		$a8 = "%s.2%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a9 = "%s.2%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a10 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii fullword
		$a11 = "Could not open service control manager on %s: %d" ascii fullword
		$a12 = "%d is an x64 process (can't inject x86 content)" ascii fullword
		$a13 = "%d is an x86 process (can't inject x64 content)" ascii fullword
		$a14 = "Failed to impersonate logged on user %d (%u)" ascii fullword
		$a15 = "could not create remote thread in %d: %d" ascii fullword
		$a16 = "%s.1%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a17 = "could not write to process memory: %d" ascii fullword
		$a18 = "Could not create service %s on %s: %d" ascii fullword
		$a19 = "Could not delete service %s on %s: %d" ascii fullword
		$a20 = "Could not open process token: %d (%u)" ascii fullword
		$a21 = "%s.1%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a22 = "Could not start service %s on %s: %d" ascii fullword
		$a23 = "Could not query service %s on %s: %d" ascii fullword
		$a24 = "Could not connect to pipe (%s): %d" ascii fullword
		$a25 = "%s.1%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a26 = "could not spawn %s (token): %d" ascii fullword
		$a27 = "could not open process %d: %d" ascii fullword
		$a28 = "could not run %s as %s\\%s: %d" ascii fullword
		$a29 = "%s.1%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a30 = "kerberos ticket use failed:" ascii fullword
		$a31 = "Started service %s on %s" ascii fullword
		$a32 = "%s.1%08x%08x%08x.%x%x.%s" ascii fullword
		$a33 = "I'm already in SMB mode" ascii fullword
		$a34 = "could not spawn %s: %d" ascii fullword
		$a35 = "could not open %s: %d" ascii fullword
		$a36 = "%s.1%08x%08x.%x%x.%s" ascii fullword
		$a37 = "Could not open '%s'" ascii fullword
		$a38 = "%s.1%08x.%x%x.%s" ascii fullword
		$a39 = "%s as %s\\%s: %d" ascii fullword
		$a40 = "%s.1%x.%x%x.%s" ascii fullword
		$a41 = "beacon.x64.dll" ascii fullword
		$a42 = "%s on %s: %d" ascii fullword
		$a43 = "www6.%x%x.%s" ascii fullword
		$a44 = "cdn.%x%x.%s" ascii fullword
		$a45 = "api.%x%x.%s" ascii fullword
		$a46 = "%s (admin)" ascii fullword
		$a47 = "beacon.dll" ascii fullword
		$a48 = "%s%s: %s" ascii fullword
		$a49 = "@%d.%s" ascii fullword
		$a50 = "%02d/%02d/%02d %02d:%02d:%02d" ascii fullword
		$a51 = "Content-Length: %d" ascii fullword

		$b1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00 }

		$c1 = { 25 FF FF FF 00 3D 41 41 41 00 75 [5-10] 25 FF FF FF 00 3D 42 42 42 00 75 }
		$c2 = { 25 FF FF FF 00 3D 41 41 41 00 75 [4-8] 81 E1 FF FF FF 00 81 F9 42 42 42 00 75 }
		$c3 = { 81 E1 FF FF FF 00 81 F9 41 41 41 00 75 [4-8] 81 E2 FF FF FF 00 81 FA 42 42 42 00 75 }
		$c4 = { 89 44 24 20 48 8B 44 24 40 0F BE 00 8B 4C 24 20 03 C8 8B C1 89 44 24 20 48 8B 44 24 40 48 FF C0 }
		$c5 = { 83 C4 04 89 45 FC 8B 4D 08 0F BE 11 03 55 FC 89 55 FC 8B 45 08 83 C0 01 89 45 08 8B 4D 08 0F BE }

		$d1 = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03 }
		$d2 = { 4C 8B 07 B8 4F EC C4 4E 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 38 10 42 30 0C 06 48 }
		$d3 = { 8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2 }
		$d4 = { 8B 06 8D 3C 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 32 08 30 07 41 3B 4D 08 72 E6 8B 45 FC EB C7 }
		$d5 = { 8B 07 8D 34 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 3A 08 30 06 41 3B 4D 08 72 E6 8B 45 FC EB }

		$e1 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D ?? FF FF FF 48 81 C3 ?? ?? 00 00 FF D3 }
		$e2 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 }

		$f1 = "User-Agent:"
		$f2 = "wini"
		$f3 = "5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii fullword
		$f4 = /[^0-9";.\/]([0-9]{1,3}\.){3}[0-9]{1,3}[^0-9";.\/]/

		$g1 = "%c%c%c%c%c%cMSSE-%d-server"
		$g2 = "ConnectNamedPipe"
		$g3 = "CreateNamedPipeA"
		$g4 = "TlsGetValue"

		$h1 = { 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4D 53 53 45 2D 25 64 2D 73 65 72 76 65 72 }

	condition:
		6 of ($a*) or
		1 of ($b*) or
		1 of ($c*) or
		1 of ($d*) or
		1 of ($e*) or
		all of ($f*) or
		( all of ( $g* ) and filesize < 500KB ) or
		all of ($h*)
}
