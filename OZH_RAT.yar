/*
	Yara Rule Set
	Author: @BushidoToken
	Date: 2020-06-05
	Identifier: OZH RAT
*/

rule OZH_RAT 
{

    meta:
        description = "Detects OZH RAT"
        author = "@BushidoToken"
        reference = "https://blog.bushidotoken.net/2020/05/ozh-rat-new-net-malware.html"
        date = "2020-06-05"
        hash1 = "15f39214b98241e7294b77d26e374e103b85ef1f189fb3ab162bda4b3423dd6c"
        hash2 = "b2ba16bcd7cb9a884f52420b1e025fc2af2610cf4324847366cc9c45e79c61c1"

    strings:
        $a = "OzhSecSys.My" nocase
        $b = "OzhSecSys.My.Resources" nocase
	$c = "OzhSecSys.pdb" nocase
        
    condition:
       any of them
}
