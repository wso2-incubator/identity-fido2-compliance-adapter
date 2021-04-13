# identity-fido2-compliance-adapter

## Features

- Map Registration and Authentication requests
- User Creation
- Metadata Service

## Tech

- [node.js] - Server implementation
- [Express] - Node.js framework


## Installation

fido2-compliance-adapter requires **Node.js** to run.

Clone the Github Project

```sh
git clone <github link>
```

Install the dependencies and devDependencies and start the server.

```sh
cd /fido2-adapter
npm install
```

Add Sample App ID to the adapter

```sh
Open  `config.json`
Change sampleAppId to your sample app id
Change the other configurations if needed
```

Start the Adapter

```sh
npm start
```

### Add Certificates

Install **openssl**

Generate Certificate

```sh
cd /security
openssl req -nodes -new -x509 -keyout server.key -out server.cert
```

Allow unauthorized TLS
```sh
export NODE_TLS_REJECT_UNAUTHORIZED='0'
```

Restart server