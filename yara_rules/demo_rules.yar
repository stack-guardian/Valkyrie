rule DemoBadFile {
  strings:
    $s = "THIS_IS_A_TEST_BAD_FILE"
  condition:
    $s
}
