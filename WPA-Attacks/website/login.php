<?php

// check if password is equal to verify
if ($_POST['password'] == $_POST['verify']) {
    $myfile = fopen("/home/kali/Desktop/password.txt", "w") or die("Unable to open file!");
    fwrite($myfile, $_POST['password']);
    fclose($myfile);
    echo "Password is set";
} else {
    echo "Password is not set";
}

?>