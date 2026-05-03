<?php
$password = "adminpassword1234"; // ለምሳሌ: Admin@123
$hash = password_hash($password, PASSWORD_DEFAULT);
echo "Password Hash: " . $hash;
?>