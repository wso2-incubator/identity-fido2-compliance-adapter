import axios from "axios";
import express from "express";
import encode from "nodejs-base64-encode";

const qs = require("qs");

const config = require("./../../config.json");
const userOps = require("./user");

let authClient: any;
let token: any;
let invalidUsername: boolean = false;
let providedUsername = "";

export default ({ app }: { app: express.Application }) => {
    /**
     * Health Check endpoints.
     */
    app.get("/status", (req, res) => {
        res.status(200).end("Connection Successful");
    });
    app.head("/status", (req, res) => {
        res.status(200).end();
    });

    /**
     * Credential Creation Options.
     */
    const appId = "{'appId':'http://localhost:61904'}";
    let requestId;

    app.post("/attestation/options", async (req, res) => {
        console.log("\nRequest @ /attestation/options");
        console.log("user >> ", req.body.username, req.body.displayName);

        const extensions = req.body.extensions;
        const attestationLogic = req.body.attestation == "direct" ? "direct" : "none";
        let username = userOps.formatUsername(req.body.username);

        invalidUsername = username[0];
        username = username[1];
        providedUsername = req.body.username;

        // Set user data required to create a user in wso2is.
        const userData = {
            familyName: req.body.displayName.split(" ")[1],
            givenName: req.body.displayName.split(" ")[0],
            homeEmail: req.body.displayName.split(" ")[0].toLowerCase() + "_home@gmail.com",
            password: config.userPassword,
            userName: username,
            workEmail: req.body.displayName.split(" ")[0].toLowerCase() + "_work@gmail.com"
        };

        // Create user.
        const userCreationResponse = await userOps.createUser(userData);

        if (!userCreationResponse) {
            res.send({
                errorMessage: "Unable to create a user",
                status: "failed"
            });
        }

        authClient = encode.encode(`${config.clientID}:${config.clientSecret}`, "base64");
        const url = "https://" + config.host + (config.tenantName && config.tenantName !== ""
            ? "/t/" + config.tenantName + "/" : "/") + "oauth2/token";
        const headers = {
            Authorization: `Basic ${authClient}`,
            "Content-Type": "application/x-www-form-urlencoded"
        };
        const data = qs.stringify({
            grant_type: "password",
            password: userData.password,
            scope: "internal_login",
            username: userData.userName
        });

        // Obtain an access token using the password grant call and 'internal_login' scope.
        await axios({
            data: data,
            headers: headers,
            method: "post",
            url: url
        }).then((response) => {
            token = response.data["access_token"];
        }).catch((error) => {
            console.log("Error while retrieving access token", error);
        });

        if (req.body.authenticatorSelection && req.body.authenticatorSelection.requireResidentKey == false) {
            // start-registration.
            const url = "https://" + config.host + (config.tenantName && config.tenantName !== ""
                ? "/t/" + config.tenantName + "/" : "/") + "api/users/v2/me/webauthn/start-registration";
            const headers = {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/x-www-form-urlencoded"
            };

            await axios({
                data: appId,
                headers: headers,
                method: "post",
                url: url
            }).then((usernamelessRegistrationResponse) => {
                requestId = usernamelessRegistrationResponse.data.requestId;

                const user = usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.user;

                if (config.isCloudSetup) {
                    if (invalidUsername) {
                        user.name = providedUsername;
                    } else {
                        user.name = user.name.split("@")[0].substring(4);
                    }
                }

                // Construct response to the conformance tools.
                const returnData = {
                    attestation: attestationLogic,
                    authenticatorSelection: {
                        requireResidentKey: usernamelessRegistrationResponse.data
                            .publicKeyCredentialCreationOptions.authenticatorSelection.requireResidentKey,
                        userVerification: usernamelessRegistrationResponse.data
                            .publicKeyCredentialCreationOptions.authenticatorSelection.userVerification
                    },
                    challenge: usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.challenge,
                    errorMessage: "",
                    excludeCredentials: usernamelessRegistrationResponse.data
                        .publicKeyCredentialCreationOptions.excludeCredentials,
                    extensions: extensions,
                    pubKeyCredParams: usernamelessRegistrationResponse.data
                        .publicKeyCredentialCreationOptions.pubKeyCredParams,
                    rp: usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.rp,
                    status: "ok",
                    timeout: usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.timeout,
                    user: user
                };

                res.send(returnData);
            }).catch((err) => {
                res.send({
                    errorMessage: err.message,
                    status: "failed"
                });
            });
        } else {
            // start-usernameless-registration.
            const url = "https://" + config.host + (config.tenantName && config.tenantName !== "" 
                ? "/t/" + config.tenantName + "/" : "/") + "api/users/v2/me/webauthn/start-usernameless-registration";
            const headers = {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/x-www-form-urlencoded"
            };

            await axios({
                data: appId,
                headers: headers,
                method: "post",
                url: url
            }).then((usernamelessRegistrationResponse) => {
                requestId = usernamelessRegistrationResponse.data.requestId;

                const user = usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.user;

                if (config.isCloudSetup) {
                    if (invalidUsername) {
                        user.name = providedUsername;
                    } else {
                        user.name = user.name.split("@")[0].substring(4);
                    }
                }

                // Response to the conformance tool.
                const returnData = {
                    attestation: usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.attestation,
                    authenticatorSelection: usernamelessRegistrationResponse.data
                        .publicKeyCredentialCreationOptions.authenticatorSelection,
                    challenge: usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.challenge,
                    errorMessage: "",
                    excludeCredentials: usernamelessRegistrationResponse.data
                        .publicKeyCredentialCreationOptions.excludeCredentials,
                    extensions: usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.extensions,
                    pubKeyCredParams: usernamelessRegistrationResponse.data
                        .publicKeyCredentialCreationOptions.pubKeyCredParams,
                    rp: usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.rp,
                    status: "ok",
                    timeout: usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.timeout,
                    user: user
                };

                res.send(returnData);
            }).catch((err) => {
                console.log(">>> err >>> ", err);

                res.send({
                    errorMessage: err.message,
                    status: "failed"
                });
            });
        }
    });

    /**
     * Authenticator Attestation Response.
     */
    app.post("/attestation/result", async (req, res) => {
        console.log("\nRequest @ /attestation/results");

        // Arrange data to be sent to the server.
        const data = {
            credential: {
                clientExtensionResults: req.body.getClientExtensionResults ?? {},
                id: req.body.id,
                response: req.body.response,
                type: req.body.type
            },
            requestId: requestId
        };

        /**
         * These parameters are not supported by the yubico data structure. Therefore need to remove before 
         * sending to the backend implementation. Otherwise will throw data conversion exception.
         */
        if (data.credential && data.credential.response && data.credential.response.getTransports) {
            delete data.credential.response.getTransports;
        }
        if (data.credential && data.credential.response && data.credential.response.getAuthenticatorData) {
            data.credential.response.authenticatorData = data.credential.response.getAuthenticatorData;
            delete data.credential.response.getAuthenticatorData;
        }
        if (data.credential && data.credential.response && data.credential.response.getPublicKey) {
            delete data.credential.response.getPublicKey;
        }
        if (data.credential && data.credential.response && data.credential.response.getPublicKeyAlgorithm) {
            delete data.credential.response.getPublicKeyAlgorithm;
        }

        // Finish registration request.
        const url = "https://" + config.host + (config.tenantName && config.tenantName !== ""
            ? "/t/" + config.tenantName + "/" : "/") + "api/users/v2/me/webauthn/finish-registration";
        const headers = {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json"
        };

        await axios({
            data: data,
            headers: headers,
            method: "post",
            url: url
        }).then(() => {
            res.send({
                errorMessage: "",
                status: "ok"
            });
        }).catch((error) => {
            res.send({
                errorMessage: error.message,
                status: "failed"
            });
        });
    });

    /**
     * Delete users.
     */
    app.delete("/adapter/users/delete", async (req, res) => {
        console.log("\nRequest @ /adapter/users/delete");

        userOps.deleteUsers().then((response) => {
            res.send({
                message: response,
                status: "success"
            });
        }).catch((error) => {
            res.send({
                errorMessage: error,
                status: "failed"
            });
        });
    });
};
