Esta vulnerabilidad se basa en no implementar adecuadamente el proceso de selección de números primos para RSA. El método adecuado consiste en 
escoger uniformemente un número en un intervalo y después comprobar que sea primo mediante Miller Rabin con una certeza suficiente. 
El método malo consiste en buscar en el intervalo pero no hacer Miller Rabin. 

  Agreed_Primes_c.cpp -> 177-220 busca uniformemente en un intervalo y comprueba con Miller Rabin si es primo
  Agreed_Primes_nc.cpp -> Busca en el intervalo pero no hace Miller Rabin