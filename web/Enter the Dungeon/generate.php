<?php

$i = 0;

do {
	$tohash = "0e".$i;
	$i++;
} while(md5($tohash) != $tohash);

echo $tohash . " = " . md5($tohash);