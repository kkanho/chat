### Chat - Group_39
A secure chat web application

## Available Scripts
```sh
#Clone this repository or unzip the repository(chat)
git clone https://github.com/kkanho/chat

#Change to the correct directory
cd chat

#Build the server through docker
docker-compose up --build
```
To view it in the browser,
open [http://group-39.comp3334.xavier2dc.fr:8080/](http://group-39.comp3334.xavier2dc.fr:8080/)
or with TLSv1.3 [https://group-39.comp3334.xavier2dc.fr:8433/](https://group-39.comp3334.xavier2dc.fr:8433/)

If any errors, try to restart multiple times with the following command
```sh
docker-compose down

docker-compose up --build
```

## Features

### Part 1 - Authentication
- [x] User-chosen memorized Secret (password/passphrase)
- [x] Single-Factor OTP Device (Google Authenticator)
- [x] Look-Up Secrets (recovery keys)
- [x] Password salted and hashed 
- [x] Password verifiers - check against corpus form haveibeenpwned api
- [x] Implement rate-limiting mechanisms
- [x] Image-based CAPTCHAs
- [x] OTP bind to new account when registration
- [x] Implement proper session binding requirements
- [ ] Provide a way to change authenticators after account registration

### Part 2 - E2EE chat
- [x] ECDH key exchange - establish a shared secret between two users
- [x] Underlying curve - P-384
- [x] Two 256-bit AES-GCM encryption keys
- [x] Two 256-bit MAC keys
- [x] Share secret using HKDF-SHA256
- [x] Unique salt for each message
- [x] Represent the info using JSON, console log in dev tools
- [x] Message encrypted using AES in GCM mode
- [x] All key material stored in local storage
- [x] All history messages should be display
- [x] Refresh button - re-derived all the symmetric key and IV and with a new salt
- [x] Keep all old keys in local storage for next login
- [x] Error message notify the user if the key is not found/cleared
- [ ] Protected against CSRF or XSS or SQL injection

### Part 3 - TLS
- [x] Communications encrypted - protect data in transit  with TLSv1.3

To use TLS in your own browser, set the root CA(COMP3334 Project Root CA 2024) to always trust

- ![image](https://github.com/kkanho/chat/assets/97432128/3fa19122-46fa-4463-bc2a-c8f991a7bd00)
- ![image](https://github.com/kkanho/chat/assets/97432128/b23cf8de-8785-46b3-b782-c267608d87ca)

### Webapp (Front-end)
- [x] Ability to sign up, login and logout
- [x] zxcvbn password strength meter
