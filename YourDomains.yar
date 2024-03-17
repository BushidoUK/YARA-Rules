rule YourDomains
{
	meta:
        description = "Checks for Domains in Files on VT"
        author = "@BushidoToken"
        reference = "https://isc.sans.edu/forums/diary/Hunting+for+Juicy+Information/20555/"
        date = "2022-06-23"

    strings:
        $domain1 = "example.com" nocase wide ascii
        $domain2 = "example.net" nocase wide ascii
        $domain3 = "example.org" nocase wide ascii
    condition:
        any of them
}
