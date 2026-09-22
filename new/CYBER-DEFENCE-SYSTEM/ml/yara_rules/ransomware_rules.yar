rule Ransom_Note_File {
  meta:
    author = "CyberShield PoC"
    description = "Detect basic ransom note patterns and common ransom extensions"

  strings:
    $a = "Your files have been encrypted" wide ascii
    $b = "For recovery instructions" wide ascii
    $c = "contact" wide ascii
    $ext_locked = /.locked$/ ascii
    $ext_encrypted = /.encrypted$/ ascii

  condition:
    any of ($a, $b, $c) or $ext_locked or $ext_encrypted
}
