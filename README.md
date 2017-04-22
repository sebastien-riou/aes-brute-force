# aes-brute-force
Using Intel AES-NI and c++ threads to search AES128 keys


## Demo Windows with Intel(R) Core(TM) i7-4770K CPU @ 3.50GHz
```
F:\aes-brute-force>build_test.bat

F:\aes-brute-force>c++ -Ofast -std=c++11 -Wall -march=native
 ./test/aes-brute-force.cpp -I ./include -lpthread -o aes-brute-force.exe


F:\aes-brute-force>aes-brute-force.exe
AES128 encryption key brute force search
Usage: aes-brute-force.exe <key_mask> <key_in> <plain> <cipher> [n_threads]

launching test/demo...

aes-brute-force.exe FF0000FF_00FF0000_0000FF00_00000000 007E1500_2800D2A6_ABF700
88_09CF4F3C 3243F6A8_885A308D_313198A2_E0370734 3925841D_02DC09FB_DC118597_196A0
B32

INFO: 8 concurrent threads supported in hardware.

Search parameters:
        n_threads:    8
        key_mask:     FF0000FF_00FF0000_0000FF00_00000000
        key_in:       007E1500_2800D2A6_ABF70088_09CF4F3C
        plain:        3243F6A8_885A308D_313198A2_E0370734
        cipher:       3925841D_02DC09FB_DC118597_196A0B32

        jobs_key_mask:000000FF_00FF0000_0000FF00_00000000

Launching 32 bits search
This can take a couple of minutes on slow computers.

Thread 1 claims to have found the key
        key found:    2B7E1516_28AED2A6_ABF71588_09CF4F3C

Performances:
        1595256342 AES128 operations done in 17.4231s
        10ns per AES128 operation
        91.56 million keys per second
INFO: found the expected key, test passed.
```

## Demo on Linux within Virtual Box / 1CPU (Host being Windows with Intel(R) Core(TM) i7-4770K CPU @ 3.50GHz)
```
user@user-VirtualBox:~/aes-brute-force$ ./build_test.sh
user@user-VirtualBox:~/aes-brute-force$ ./aes-brute-force
AES128 encryption key brute force search
Usage: ./aes-brute-force <key_mask> <key_in> <plain> <cipher> [n_threads]

launching test/demo...

./aes-brute-force FF0000FF_00FF0000_0000FF00_00000000 007E1500_2800D2A6_ABF70088_09CF4F3C 3243F6A8_885A308D_313198A2_E0370734 3925841D_02DC09FB_DC118597_196A0B32

INFO: 1 concurrent threads supported in hardware.

Search parameters:
	n_threads:    1
	key_mask:     FF0000FF_00FF0000_0000FF00_00000000
	key_in:       007E1500_2800D2A6_ABF70088_09CF4F3C
	plain:        3243F6A8_885A308D_313198A2_E0370734
	cipher:       3925841D_02DC09FB_DC118597_196A0B32

	jobs_key_mask:FF0000FF_00FF0000_0000FF00_00000000

Launching 32 bits search
This can take a couple of minutes on slow computers.

Thread 0 claims to have found the key
	key found:    2B7E1516_28AED2A6_ABF71588_09CF4F3C

Performances:
	363730475 AES128 operations done in 40.3497s
	110ns per AES128 operation
	9.01 million keys per second
INFO: found the expected key, test passed.
```
