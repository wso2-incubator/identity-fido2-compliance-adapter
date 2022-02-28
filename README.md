# identity-fido2-compliance-adapter

## Features

- Map Registration and Authentication requests
- User Creation
- Metadata Service

## Tech

- [node.js] - Server implementation
- [Express] - Node.js framework

## Setup Guide

### Downloading and Installation - FIDO Conformance tools

1. Request FIDO Conformance tools from FIDO Alliance.

```sh
https://fidoalliance.org/test-tool-access-request/
```

2. Download and install the FIDO conformance tools from FIDO Alliance.

Note : Tools (v1.5.2) will work only on macOS and Windows.

### Adater Setup

fido2-compliance-adapter requires **Node.js** to run.

1. Clone the Github Project

```sh
git clone <github link>
```

2. Install the dependencies and devDependencies and start the server.

```sh
cd /fido2-adapter
npm install
```

3. Add Sample App ID to the adapter

```sh
Open  `config.json`
Change clientID to your sample application client id
Change the other configurations if needed
```

4. Start the Adapter

```sh
npm start
```

### Add Certificates

Install **openssl**

1. Generate Certificate

```sh
cd /security
openssl req -nodes -new -x509 -keyout server.key -out server.cert
```

2. Allow unauthorized TLS

```sh
export NODE_TLS_REJECT_UNAUTHORIZED='0'
```

3. Restart server

### WSO2 Identity Server and Sample App Setup

1.  Start WSO2 IS

2.  Setup the sample application (Pickup-Dispatch App)

    Refer WSO2 IS Deploying the Sample Applications documentation to deploy the pickup-dispatch webapp.

    ```sh
        https://is.docs.wso2.com/en/5.9.0/learn/deploying-the-sample-app/
    ```

    After successful deployment, enable login with FIDO2 for the deployed pickup-dispatch webapp.
    login to Management console

    ```sh
        Username : admin
        Password : admin
    ```

    Select Service Providers -> List. Then click edit for the deployed application. Select Local & Outbound Authentication Configuration and click Local Authentication as fido.

    Add any claim configuration you prefer under Claim Configuration tab to enable consent page.

    Update the settings and reload the WSO2 IS server.

### Run the FIDO conformance tool

1. Start FIDO Conformance tool

2. Select **FIDO2.0 Tests**

3. Add the server URL under TEST CONFIGURATIONS - Server URL

   ```sh
       https://localhost:4000
   ```

4. Download server metadata by clicking DOWNLOAD SERVER METADATA button
5. Extract the downloaded metadata statements and copy them to the fido-conformance-mds folder in the adapter
6. Select the required test cases under Server Tests

7. Click RUN to start the testing process
