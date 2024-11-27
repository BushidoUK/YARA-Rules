rule universalminer_loader
{
meta:
  description = "Looks like UniversalMiner malware botnet loaders"
  author = "Will Thomas, ETAC, @BushidoToken"
  reference = "https://mrl.cert.gov.az/az/articles/view/125"
  hash = "1241ff4b7abe17e0e2b827b9ed42d1bc91e0b0627c674c008afb08435e290346"
  created = "2024-NOV-27"
  TLP = "CLEAR"

strings:
  $str1 = "mkdir" ascii wide nocase
  $str2 = "printui.exe" ascii wide nocase
  $str3 = "xcopy" ascii wide nocase
  
condition:
    all of ($str*)
}
