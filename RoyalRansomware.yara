import "vt"
rule RoyalRansomware
{
  meta:
      description = "Checks for Royal Ransomware notes"
      author = "@BushidoToken"
      source = "https://github.com/curated-intel/Detection-Rule-Exchange"
      reference = "https://www.bleepingcomputer.com/news/security/new-royal-ransomware-emerges-in-multi-million-dollar-attacks/"
      created = "2022-06-29"
      TLP = "CLEAR"
  
  strings:
      $a = "royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion"
      $b = "Try Royal today and enter the enew era of data security!"
      $c = "Royal offers you a unique deal.For a modest royalty(got it; got ? ) for our pentesting services"
  condition:
      any of them
      and not vt.metadata.file_type == vt.FileType.JAVASCRIPT or vt.FileType.HTML
      and vt.metadata.new_file
}
