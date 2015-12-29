<?php

$passwordHash = '{X-PBKDF2}HMACSHA1:AAAD6A:p7YR2A==:t8vhONw0jlsmLnZH9JoRkXFOdLM=';
$password = '5555';

parsedHash($passwordHash);

function parsedHash($passwordHash) {
	global $password;

	$parts = explode(':', $passwordHash);
	$algorithm = preg_replace('#^{.+}#si', '', $parts[0]);

	$algorithm = str_replace('hmac', '', strtolower($algorithm));

	$salt = base64_decode($parts[2]);
	$hash = base64_decode($parts[3]);
	$iterations = getIterations($parts[1]);

	$hashed = hash_pbkdf2($algorithm, $password, $salt, $iterations, strlen($hash), true);

	return $hash == $hashed;
}

function getIterations($iterationHash) {
	$base64Decoded = base64_decode($iterationHash);

	$unpacked = unpack('N', $base64Decoded);
	return $unpacked[1];
}