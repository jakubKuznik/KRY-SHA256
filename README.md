# SHA256 
## Faculty: BUT FIT, Course: KRY

Name: Jakub Kuznik  
Login: xkuzni04  

# Points 
9.62/10

# About 

This tool computes SHA256 for a given input and also implements the length extension attack. The implementation aims to provide readable code for educational purposes, not optimized code.

Program reads from STDIN and print output to STDOUT. 

## Execution  
```./kry {-c | -s | -v | -e} [-k KEY] [-m CHS] [-n NUM] [-a MSG]```
```
    -c
        Count the SHA-256 of input message.
    -s
        Count MAC of input messgae using SHA-256.
    -v -m CHS -k KEY
        Validate MAC (-m) for given key (-k) and returns 0 if valid else 1.
    -e -m CHS -n NUM -a MSG
        Execute the Length Extension Attack on given MAC (-m) and
        input message (-a), it uses the key length (-n)

    -k KEY
           Specify secret key for MAC calculation. 
           KEY format: ^[A-Fa-f0-9]*$
    -m CHS
           Specify MAC of the input message for its verification or 
           attack execution.
    -n NUM
           Specify length of the secret key
    -a MSG
           Specify extension of input message for attack execution.
           MSG format: ^[a-zA-Z0-9!#$%&\'\"()*+,\\-.\\/:;<>=?@[\\]\\\\^_{}|~]*$
```

## Example usage 

Generate SHA256 for message `zprava`
```
echo -ne "zprava" | ./kry -c 
```
Desired Output:
```
d8305a064cd0f827df85ae5a7732bf25d578b746b8434871704e98cde3208ddf
```

Generate SHA256 for message `zprava` with passwrod `heslo`
```
echo -ne "zprava" | ./kry -s -k heslo
```
Desired Output:
```
23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e
```

Validate SHA256 of message `zprava` and `return 0` if hash is correct. 
```
echo -ne "zprava" | ./kry -v -k heslo -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e
```
Desired Output:
```
echo $?
0
```

Do the Lengh extension attack and append `==mesage` to original message. 
```
echo -ne "zprava" | ./kry -e -n 5 -a ==message -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e
```
Desired Output:
```
a3b205a7ebb070c26910e1028322e99b35e846d5db399aae295082ddecf3edd3
zprava\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x
00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x
00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x
00\x00\x00\x00\x00\x00\x58==message
```

## Sources 
https://sha256algorithm.com/  
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf




