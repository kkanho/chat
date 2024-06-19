### Chat - Group_39
A secure chat web application

# Demonstration videos:
[![ATM demo](https://img.youtube.com/vi/Pk3HRQ5v5B4/0.jpg)](https://www.youtube.com/watch?v=Pk3HRQ5v5B4)


## Available Scripts
```sh
#Clone this repository(chat)
git clone https://github.com/kkanho/chat

#Change to the correct directory
cd chat

#Build the server through docker
docker-compose up --build
```
To view it in the browser,
open [http://group-39.comp3334.xavier2dc.fr:8080/](http://group-39.comp3334.xavier2dc.fr:8080/)
or with TLSv1.3 [https://group-39.comp3334.xavier2dc.fr:8443/](https://group-39.comp3334.xavier2dc.fr:8443/)

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
- [x] Provide a way to change authenticators after account registration

### Part 2 - E2EE chat
- [x] ECDH key exchange - establish a shared secret between two users
- [x] Underlying curve - P-384
- [x] Derive two 256-bit AES-GCM encryption keys
- [x] Derive two 256-bit MAC keys
- [x] Share secret using HKDF-SHA256
- [x] Unique salt for each message
- [x] Represent the info using JSON, console log in dev tools
- [x] Message encrypted using AES in GCM mode
- [x] Prevent replay attacks as a recipient
- [x] All key material stored in local storage
- [x] All history messages should be display
- [x] Show warning if previous messages cannot be decrypted
- [x] Refresh button - re-derived all the symmetric key and IV and with a new salt
- [x] Keep all old keys in local storage for next login
- [x] Error message notify the user if the key is not found/cleared
- [x] Protected against CSRF or XSS or SQL injection (samesite: lax)

### Part 3 - TLS
- [x] Communications encrypted - protect data in transit with TLSv1.3

To use TLS in your own browser, set the root CA(COMP3334 Project Root CA 2024) to always trust
<!--- 
- ![image](https://github.com/kkanho/chat/assets/97432128/3fa19122-46fa-4463-bc2a-c8f991a7bd00)
- ![image](https://github.com/kkanho/chat/assets/97432128/b23cf8de-8785-46b3-b782-c267608d87ca)
              -->
### Webapp (Front-end)
- [x] Ability to sign up, login and logout
- [x] zxcvbn password strength meter


