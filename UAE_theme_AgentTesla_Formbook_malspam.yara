import "vt"
rule UAE_theme_AgentTesla_Formbook_malspam
{
  meta:
    description = "Checks for maldocs created by DONOR1 who leverages UAE companies in attacks"
    author = "Will Thomas, Equinix Threat Analysis Center (ETAC)"
    hash1 = "5ee7fd5471977f47c04d0ea7456979d750ee3b215163287a95534954dc6c957b"
    hash2 = "e3dacfe903996e17272145222ddf82ae88fe02ddef2fcaf7d7c6e3d4b834bb42"
    hash3 = "61535c9d50244a39616537f515e0f7a376870ef7f8a6862ffd4624837fbe7a92"
    created = "2022-11-24"
    tlp = "CLEAR"
  
  condition:
    vt.metadata.exiftool["LastModifiedBy"] == "DONOR1" 
    and vt.metadata.exiftool["Creator"] == "DONOR1"
    and vt.metadata.new_file
}
