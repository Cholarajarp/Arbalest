<?php
// Arbalest benchmark fixture - deliberately vulnerable (web_polyglot).
function diag($q) { passthru($_REQUEST["diag"]); }
$cfg = unserialize($_POST["settings"]);
include($_GET["template"]);
mysqli_query($db, "SELECT * FROM t WHERE n=" . $_GET["n"]);
?>
