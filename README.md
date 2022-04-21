# identity-fido2-compliance-adapter

## Features

- Map Registration and Authentication requests
- User Creation and Deletion
- Host Interoperability Web App

## Tech

- [node.js] - Server implementation
- [Express] - Node.js framework

## Setup Guide

### Setup FIDO Conformance Testing Tool

1. [Request FIDO conformance testing tool](https://fidoalliance.org/test-tool-access-request/) from FIDO Alliance.

2. Download and install the FIDO conformance testing tool.

3. Launch the application and select **FIDO2 Server - MDS3 Tests**.

3. Enter `https://localhost:4000` as the server url.

> Note: Tool (v1.6.42 experimental) will work only on macOS and Windows operating systems.

### Setup Identity Server

1. Download and start WSO2 identity server and login to the console. Alternatively login to Asgardeo for cloud setup.

2. Create a sample application for conformance testing.

### Compliance Adapter Setup

> fido2-compliance-adapter requires **Node.js** to run.

1. Clone the github project.
```sh
git clone git@github.com:wso2-incubator/identity-fido2-compliance-adapter.git
```

2. Install dependencies by executing the following command.
```sh
cd /identity-fido2-compliance-adapter
npm install
```

3. Configure the adapter by adding following configs to the `config.json` file.

| Configuration | Description | Sample value |
| -- | -- | -- |
| `clientID` | The client ID of the application created | `ZECYcLyBtHDkLtpOSSXKF85jQ2sa` |
| `clientSecret` | The client secret of the application created | `1_6rdIRx5U3F3mTyKL19vTW9lD0a` |
| `host` | Host address of the server | `127.0.0.1` (`api.asgardeo.io` for cloud) |
| `tenantName` | Name of the tenant/ organization. Leave this empty if you're not configuring in a tenant environment | `myorg` |
| `redirectUri` | Redirect url provided for the created application | `http://localhost.com:8080/pickup-dispatch/oauth2client` |
| `basicAuthCredentials` | Base64 encoded `username:password` for the basic authentication (Only requires in on-prem setup) | `YWRtaW46YWRtaW4=` |
| `authRequestRefererHost` | Referer host to be sent in the authentication request. Cannot use an ip address for this field | `localhost` (`accounts.asg.io` for cloud) |
| `userPassword` | Password for the adapter created user accounts. No need to change this value unless you have enforced different password policies. | `User@123` |
| `isCloudSetup` | Boolean indicating whether you're running the adapter against cloud setup or on-prem setup | `false` |
| `bearerTokenGrantType` | Grant type required to obtain bearer token (Only requires in cloud setup) |  |
| `bearerTokenClientId` | Client ID to obtain bearer token (Only requires in cloud setup) |  |
| `bearerTokenUsername` | Username to obtain bearer token (Only requires in cloud setup) |  |
| `bearerTokenPassword` | Password of the above provided user to obtain bearer token (Only requires in cloud setup) |  |
| `bearerTokenScope` | Scope for the bearer token (Only requires in cloud setup) |  |
| `userStoreDomain` | User store domain name (Only requires in cloud setup) |  |

4. Follow below commands to add certificates to the adapter.

    - Install **openssl**.

    - Generate certificate by executing the below command.
    ```sh
    cd /security
    openssl req -nodes -new -x509 -keyout server.key -out server.cert
    ```

    - Allow unauthorized TLS by executing the below command.
    ```sh
    export NODE_TLS_REJECT_UNAUTHORIZED='0'
    ```

5. Download `index.html` file from [fido-interop-webapp](https://github.com/fido-alliance/fido2-interop-webapp) repository and copy to `src/app/interop-testing` directory.

6. Start the adapter by executing following command.
```sh
npm start
```

## Run FIDO Conformance Tests

1. Download server metadata by clicking **DOWNLOAD SERVER METADATA** button. You are required to upload the extracted metadata files to the identity server inorder to pass metadata tests.
2. Select the required test cases under **Server Tests**.
3. Click RUN to start the testing process

## Additional Configurations

### Sample App Setup in WSO2 Identity Server

1.  Start WSO2 IS

2.  Setup the sample application (Pickup-Dispatch App)

    Refer [WSO2 IS Deploying the Sample Applications documentation](https://is.docs.wso2.com/en/latest/learn/deploying-the-sample-app/#deploying-the-sample-applications) to deploy the pickup-dispatch webapp.

    After successful deployment, enable login with FIDO2 for the deployed pickup-dispatch webapp.
    login to Management console

    ```
    Username : admin
    Password : admin
    ```

    Select `Service Providers -> List`. Then click edit for the deployed application. Select Local & Outbound Authentication Configuration and click Local Authentication as fido.

    Add any claim configuration you prefer under Claim Configuration tab to enable consent page.

    Update the settings and reload the WSO2 IS server.
