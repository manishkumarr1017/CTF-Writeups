## MITM

Given description:

```
Bob Wants the secret code from the alice. After getting the secret code from alice, bob sends his secret code to alice. Can you find the secret codes of alice and bob?
```

By looking at the source code we can understand that this is Diffie Hellman algorithm. The shared key is used as the AES key and able to transmit data from Alice to Bob. As the description says that alice will be sending a code after verifying it the bob sends his code so we have to find the codes of alice and bob.

By doing some recon we can see DH is vulnerable to [man in the middle attack](https://stackoverflow.com/questions/10471009/how-does-the-man-in-the-middle-attack-work-in-diffie-hellman)

So we just have to make two DH connections by assuming our own private key and we have to get the shared key to decrypt the flag.
 