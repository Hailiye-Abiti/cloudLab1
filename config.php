<?php
// Database credentials
$servername= "localhost";
$username= "root";
$password= "";
$db_name= "feedback";

// Attempt to connect to MySQL database
// WAMP uses port 3306 by default. We use 3306 or omit the port argument.
// If your WAMP uses the default port, this line works:
$conn = new mysqli($servername, $username, $password, $db_name, 3306); 

// Check connection
if ($conn === false) {
    // If the connection fails, terminate the script and report the error.
    die("ERROR: Could not connect. " . $conn->connect_error);
}
function generate_otp() {
    return str_pad(rand(1, 999999), 6, '0', STR_PAD_LEFT);
}
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}
?>