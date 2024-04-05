import "vt"
rule SEXi_LIMPOPO_FORMOSA_SOCOTRA_ransomware
{
meta:
  description = "Checks for variants of SEXi ransomware, which uses Babuk and LockBitBlack"
  author = "Will Thomas, ETAC, @BushidoToken"
  source = "https://twitter.com/BushidoToken/status/1775843087736025175"
  reference = "https://www.virustotal.com/gui/collection/6fb52b5c2c82d3c6bd9ec45f628c278f385c5948ab251b7d9c9d5a1e7e6e2a03/summary"
  created = "2024-APRIL-05"
  TLP = "CLEAR"
  
strings:
  $a = "05c5dbb3e0f6c173dd4ca479587dbeccc1365998ff9042581cd294566645ec7912"
  $b = "go to https://getsession.org/; download & install; run, click conversations"
  $c = "mention this code FORMOSA in your initial message;"
  $d = "mention this code LIMPOPO in your initial message;"
  $e = "mention this code SOCOTRA in your initial message;"
  $f = "we have exfiltrated all your valuable data; we are going to publish it on the dark web pretty soon"

condition:
  any of them
  and not vt.metadata.file_type == vt.FileType.JAVASCRIPT or vt.FileType.HTML
  and vt.metadata.new_file
}
